// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Copyright (c) 2026 Martin Troedsson. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System;
using System.Collections.Generic;
using System.Net;
using System.Security.Claims;
using System.Threading.Tasks;
using Shouldly;
using IdentityServer.IntegrationTests.Common;
using IdentityServer4.Models;
using IdentityServer4.Stores;
using IdentityServer4.Stores.Default;
using IdentityServer4.Test;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace IdentityServer.IntegrationTests.Endpoints.Authorize
{
    public class ConsentTests
    {
        private const string Category = "Authorize and consent tests";

        private IdentityServerPipeline _mockPipeline = new IdentityServerPipeline();

        public ConsentTests()
        {
            _mockPipeline.Clients.AddRange(new Client[] {
                new Client
                {
                    ClientId = "client1",
                    AllowedGrantTypes = GrantTypes.Implicit,
                    RequireConsent = false,
                    AllowedScopes = new List<string> { "openid", "profile" },
                    RedirectUris = new List<string> { "https://client1/callback" },
                    AllowAccessTokensViaBrowser = true
                },
                new Client
                {
                    ClientId = "client2",
                    AllowedGrantTypes = GrantTypes.Implicit,
                    RequireConsent = true,
                    AllowedScopes = new List<string> { "openid", "profile", "api1", "api2" },
                    RedirectUris = new List<string> { "https://client2/callback" },
                    AllowAccessTokensViaBrowser = true
                },
                new Client
                {
                    ClientId = "client3",
                    AllowedGrantTypes = GrantTypes.Implicit,
                    RequireConsent = false,
                    AllowedScopes = new List<string> { "openid", "profile", "api1", "api2" },
                    RedirectUris = new List<string> { "https://client3/callback" },
                    AllowAccessTokensViaBrowser = true,
                    IdentityProviderRestrictions = new List<string> { "google" }
                }
            });

            _mockPipeline.Users.Add(new TestUser
            {
                SubjectId = "bob",
                Username = "bob",
                Claims = new Claim[]
                {
                    new Claim("name", "Bob Loblaw"),
                    new Claim("email", "bob@loblaw.com"),
                    new Claim("role", "Attorney")
                }
            });

            _mockPipeline.IdentityScopes.AddRange(new IdentityResource[] {
                new IdentityResources.OpenId(),
                new IdentityResources.Profile(),
                new IdentityResources.Email()
            });
            _mockPipeline.ApiResources.AddRange(new ApiResource[] {
                new ApiResource
                {
                    Name = "api",
                    Scopes = { "api1", "api2" }
                }
            });

            _mockPipeline.ApiScopes.AddRange(new ApiScope[]
            {
                new ApiScope
                {
                    Name = "api1"
                },
                new ApiScope
                {
                    Name = "api2"
                }
            });

            _mockPipeline.Initialize();
        }

        [Fact]
        [Trait("Category", Category)]
        public async Task client_requires_consent_should_show_consent_page()
        {
            await _mockPipeline.LoginAsync("bob");

            var url = _mockPipeline.CreateAuthorizeUrl(
                clientId: "client2",
                responseType: "id_token",
                scope: "openid",
                redirectUri: "https://client2/callback",
                state: "123_state",
                nonce: "123_nonce"
            );
            var response = await _mockPipeline.BrowserClient.GetAsync(url, TestContext.Current.CancellationToken);

            _mockPipeline.ConsentWasCalled.ShouldBeTrue();
        }

        [Theory]
        [InlineData((Type)null)]
        [InlineData(typeof(QueryStringAuthorizationParametersMessageStore))]
        [InlineData(typeof(DistributedCacheAuthorizationParametersMessageStore))]
        [Trait("Category", Category)]
        public async Task consent_page_should_have_authorization_params(Type storeType)
        {
            if (storeType != null)
            {
                _mockPipeline.OnPostConfigureServices += services =>
                {
                    services.AddTransient(typeof(IAuthorizationParametersMessageStore), storeType);
                };
                _mockPipeline.Initialize();
            }

            await _mockPipeline.LoginAsync("bob");

            var url = _mockPipeline.CreateAuthorizeUrl(
                clientId: "client2",
                responseType: "id_token token",
                scope: "openid api1 api2",
                redirectUri: "https://client2/callback",
                state: "123_state",
                nonce: "123_nonce",
                acrValues: "acr_1 acr_2 tenant:tenant_value",
                extra: new
                {
                    display = "popup", // must use a valid value form the spec for display
                    ui_locales = "ui_locale_value",
                    custom_foo = "foo_value"
                }
            );
            var response = await _mockPipeline.BrowserClient.GetAsync(url, TestContext.Current.CancellationToken);

            _mockPipeline.ConsentRequest.ShouldNotBeNull();
            _mockPipeline.ConsentRequest.Client.ClientId.ShouldBe("client2");
            _mockPipeline.ConsentRequest.DisplayMode.ShouldBe("popup");
            _mockPipeline.ConsentRequest.UiLocales.ShouldBe("ui_locale_value");
            _mockPipeline.ConsentRequest.Tenant.ShouldBe("tenant_value");
            _mockPipeline.ConsentRequest.AcrValues.ShouldBe(new string[] { "acr_2", "acr_1" }, ignoreOrder: true);
            _mockPipeline.ConsentRequest.Parameters.AllKeys.ShouldContain("custom_foo");
            _mockPipeline.ConsentRequest.Parameters["custom_foo"].ShouldBe("foo_value");
            _mockPipeline.ConsentRequest.ValidatedResources.RawScopeValues.ShouldBe(new string[] { "api2", "openid", "api1" }, ignoreOrder: true);
        }

        [Theory]
        [InlineData((Type)null)]
        [InlineData(typeof(QueryStringAuthorizationParametersMessageStore))]
        [InlineData(typeof(DistributedCacheAuthorizationParametersMessageStore))]
        [Trait("Category", Category)]
        public async Task consent_response_should_allow_successful_authorization_response(Type storeType)
        {
            if (storeType != null)
            {
                _mockPipeline.OnPostConfigureServices += services =>
                {
                    services.AddTransient(typeof(IAuthorizationParametersMessageStore), storeType);
                };
                _mockPipeline.Initialize();
            }

            await _mockPipeline.LoginAsync("bob");

            _mockPipeline.ConsentResponse = new ConsentResponse()
            {
                ScopesValuesConsented = new string[] { "openid", "api2" }
            };
            _mockPipeline.BrowserClient.StopRedirectingAfter = 2;

            var url = _mockPipeline.CreateAuthorizeUrl(
                clientId: "client2",
                responseType: "id_token token",
                scope: "openid profile api1 api2",
                redirectUri: "https://client2/callback",
                state: "123_state",
                nonce: "123_nonce");
            var response = await _mockPipeline.BrowserClient.GetAsync(url, TestContext.Current.CancellationToken);

            response.StatusCode.ShouldBe(HttpStatusCode.Redirect);
            response.Headers.Location.ToString().ShouldStartWith("https://client2/callback");

            var authorization = new Duende.IdentityModel.Client.AuthorizeResponse(response.Headers.Location.ToString());
            authorization.IsError.ShouldBeFalse();
            authorization.IdentityToken.ShouldNotBeNull();
            authorization.State.ShouldBe("123_state");
            var scopes = authorization.Scope.Split(' ');
            scopes.ShouldBe(new string[] { "api2", "openid" }, ignoreOrder: true);
        }

        [Fact]
        [Trait("Category", Category)]
        public async Task consent_response_should_reject_modified_request_params()
        {
            await _mockPipeline.LoginAsync("bob");

            _mockPipeline.ConsentResponse = new ConsentResponse()
            {
                ScopesValuesConsented = new string[] { "openid", "api2" }
            };
            _mockPipeline.BrowserClient.AllowAutoRedirect = false;

            var url = _mockPipeline.CreateAuthorizeUrl(
                clientId: "client2",
                responseType: "id_token token",
                scope: "openid profile api2",
                redirectUri: "https://client2/callback",
                state: "123_state",
                nonce: "123_nonce");
            var response = await _mockPipeline.BrowserClient.GetAsync(url, TestContext.Current.CancellationToken);

            response.StatusCode.ShouldBe(HttpStatusCode.Redirect);
            response.Headers.Location.ToString().ShouldStartWith("https://server/consent");

            response = await _mockPipeline.BrowserClient.GetAsync(response.Headers.Location.ToString(), TestContext.Current.CancellationToken);

            response.StatusCode.ShouldBe(HttpStatusCode.Redirect);
            response.Headers.Location.ToString().ShouldStartWith("/connect/authorize/callback");

            var modifiedAuthorizeCallback = "https://server" + response.Headers.Location.ToString();
            modifiedAuthorizeCallback = modifiedAuthorizeCallback.Replace("api2", "api1%20api2");

            response = await _mockPipeline.BrowserClient.GetAsync(modifiedAuthorizeCallback, TestContext.Current.CancellationToken);
            response.StatusCode.ShouldBe(HttpStatusCode.Redirect);
            response.Headers.Location.ToString().ShouldStartWith("https://server/consent");
        }

        [Fact()]
        [Trait("Category", Category)]
        public async Task consent_response_missing_required_scopes_should_error()
        {
            await _mockPipeline.LoginAsync("bob");

            _mockPipeline.ConsentResponse = new ConsentResponse()
            {
                ScopesValuesConsented = new string[] { "api2" }
            };
            _mockPipeline.BrowserClient.StopRedirectingAfter = 2;

            var url = _mockPipeline.CreateAuthorizeUrl(
                clientId: "client2",
                responseType: "id_token token",
                scope: "openid profile api1 api2",
                redirectUri: "https://client2/callback",
                state: "123_state",
                nonce: "123_nonce");
            var response = await _mockPipeline.BrowserClient.GetAsync(url, TestContext.Current.CancellationToken);
            response.StatusCode.ShouldBe(HttpStatusCode.Redirect);
            response.Headers.Location.ToString().ShouldStartWith("https://client2/callback");

            var authorization = new Duende.IdentityModel.Client.AuthorizeResponse(response.Headers.Location.ToString());
            authorization.IsError.ShouldBeTrue();
            authorization.Error.ShouldBe("access_denied");
            authorization.State.ShouldBe("123_state");
        }
    }
}
