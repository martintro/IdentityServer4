// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Copyright (c) 2026 Martin Troedsson. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using Duende.IdentityModel.Client;
using Shouldly;
using IdentityServer.IntegrationTests.Common;
using IdentityServer.IntegrationTests.Endpoints.Introspection.Setup;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Hosting;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Xunit;

namespace IdentityServer.IntegrationTests.Endpoints.Introspection
{
    public class IntrospectionTests
    {
        private const string Category = "Introspection endpoint";
        private const string IntrospectionEndpoint = "https://server/connect/introspect";
        private const string TokenEndpoint = "https://server/connect/token";

        private readonly HttpClient _client;
        private readonly HttpMessageHandler _handler;

        public IntrospectionTests()
        {
            var host = new HostBuilder()
                .ConfigureWebHost(builder => builder
                    .UseTestServer()
                    .UseStartup<Startup>())
                .Start();
            var server = host.GetTestServer();

            _handler = server.CreateHandler();
            _client = server.CreateClient();
        }

        [Fact]
        [Trait("Category", Category)]
        public async Task Empty_request_should_fail()
        {
            var form = new Dictionary<string, string>();

            var response = await _client.PostAsync(IntrospectionEndpoint, new FormUrlEncodedContent(form), TestContext.Current.CancellationToken);

            response.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
        }

        [Fact]
        [Trait("Category", Category)]
        public async Task Unknown_scope_should_fail()
        {
            var form = new Dictionary<string, string>();

            _client.SetBasicAuthentication("unknown", "invalid");
            var response = await _client.PostAsync(IntrospectionEndpoint, new FormUrlEncodedContent(form), TestContext.Current.CancellationToken);

            response.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
        }

        [Fact]
        [Trait("Category", Category)]
        public async Task Invalid_scope_secret_should_fail()
        {
            var form = new Dictionary<string, string>();

            _client.SetBasicAuthentication("api1", "invalid");
            var response = await _client.PostAsync(IntrospectionEndpoint, new FormUrlEncodedContent(form), TestContext.Current.CancellationToken);

            response.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
        }

        [Fact]
        [Trait("Category", Category)]
        public async Task Missing_token_should_fail()
        {
            var form = new Dictionary<string, string>();

            _client.SetBasicAuthentication("api1", "secret");
            var response = await _client.PostAsync(IntrospectionEndpoint, new FormUrlEncodedContent(form), TestContext.Current.CancellationToken);

            response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
        }

        [Fact]
        [Trait("Category", Category)]
        public async Task Invalid_token_should_fail()
        {
            var introspectionResponse = await _client.IntrospectTokenAsync(new TokenIntrospectionRequest
            {
                Address = IntrospectionEndpoint,
                ClientId = "api1",
                ClientSecret = "secret",

                Token = "invalid"
            }, cancellationToken: TestContext.Current.CancellationToken);

            introspectionResponse.IsActive.ShouldBe(false);
            introspectionResponse.IsError.ShouldBe(false);
        }

        [Fact]
        [Trait("Category", Category)]
        public async Task Invalid_Content_type_should_fail()
        {
            var tokenResponse = await _client.RequestClientCredentialsTokenAsync(new ClientCredentialsTokenRequest
            {
                Address = TokenEndpoint,
                ClientId = "client1",
                ClientSecret = "secret",
                Scope = "api1"
            }, cancellationToken: TestContext.Current.CancellationToken);

            var data = new
            {
                client_id = "api1",
                client_secret = "secret",
                token = tokenResponse.AccessToken
            };
            var json = JsonSerializer.Serialize(data);

            var client = new HttpClient(_handler);
            var response = await client.PostAsync(IntrospectionEndpoint, new StringContent(json, Encoding.UTF8, "application/json"), TestContext.Current.CancellationToken);
            response.StatusCode.ShouldBe(HttpStatusCode.UnsupportedMediaType);
        }

        [Fact]
        [Trait("Category", Category)]
        public async Task Valid_token_and_valid_scope_should_succeed()
        {
            var tokenResponse = await _client.RequestClientCredentialsTokenAsync(new ClientCredentialsTokenRequest
            {
                Address = TokenEndpoint,
                ClientId = "client1",
                ClientSecret = "secret",
                Scope = "api1"
            }, cancellationToken: TestContext.Current.CancellationToken);

            var introspectionResponse = await _client.IntrospectTokenAsync(new TokenIntrospectionRequest
            {
                Address = IntrospectionEndpoint,
                ClientId = "api1",
                ClientSecret = "secret",

                Token = tokenResponse.AccessToken
            }, cancellationToken: TestContext.Current.CancellationToken);

            introspectionResponse.IsActive.ShouldBe(true);
            introspectionResponse.IsError.ShouldBe(false);

            var scopes = from c in introspectionResponse.Claims
                         where c.Type == "scope"
                         select c;

            scopes.Count().ShouldBe(1);
            scopes.First().Value.ShouldBe("api1");
        }

        [Fact]
        [Trait("Category", Category)]
        public async Task Response_data_should_be_valid_using_single_scope()
        {
            var tokenResponse = await _client.RequestClientCredentialsTokenAsync(new ClientCredentialsTokenRequest
            {
                Address = TokenEndpoint,
                ClientId = "client1",
                ClientSecret = "secret",
                Scope = "api1"
            }, cancellationToken: TestContext.Current.CancellationToken);

            var introspectionResponse = await _client.IntrospectTokenAsync(new TokenIntrospectionRequest
            {
                Address = IntrospectionEndpoint,
                ClientId = "api1",
                ClientSecret = "secret",

                Token = tokenResponse.AccessToken
            }, cancellationToken: TestContext.Current.CancellationToken);

            var values = introspectionResponse.Json.Value.ToObject<Dictionary<string, JsonElement>>();

            values["aud"].ValueKind.ShouldBe(JsonValueKind.String);
            values["iss"].ValueKind.ShouldBe(JsonValueKind.String);
            values["nbf"].ValueKind.ShouldBe(JsonValueKind.Number);
            values["exp"].ValueKind.ShouldBe(JsonValueKind.Number);
            values["client_id"].ValueKind.ShouldBe(JsonValueKind.String);
            values["active"].ValueKind.ShouldBe(JsonValueKind.True);
            values["scope"].ValueKind.ShouldBe(JsonValueKind.String);

            values["scope"].ToString().ShouldBe("api1");
        }

        [Fact]
        [Trait("Category", Category)]
        public async Task Response_data_with_user_authentication_should_be_valid_using_single_scope()
        {
            var tokenResponse = await _client.RequestPasswordTokenAsync(new PasswordTokenRequest
            {
                Address = TokenEndpoint,
                ClientId = "ro.client",
                ClientSecret = "secret",
                UserName = "bob",
                Password = "bob",

                Scope = "api1",
            }, cancellationToken: TestContext.Current.CancellationToken);

            tokenResponse.IsError.ShouldBeFalse();

            var introspectionResponse = await _client.IntrospectTokenAsync(new TokenIntrospectionRequest
            {
                Address = IntrospectionEndpoint,
                ClientId = "api1",
                ClientSecret = "secret",

                Token = tokenResponse.AccessToken
            }, cancellationToken: TestContext.Current.CancellationToken);

            var values = introspectionResponse.Json.Value.ToObject<Dictionary<string, JsonElement>>();

            values["aud"].ValueKind.ShouldBe(JsonValueKind.String);
            values["iss"].ValueKind.ShouldBe(JsonValueKind.String);
            values["nbf"].ValueKind.ShouldBe(JsonValueKind.Number);
            values["exp"].ValueKind.ShouldBe(JsonValueKind.Number);
            values["auth_time"].ValueKind.ShouldBe(JsonValueKind.Number);
            values["client_id"].ValueKind.ShouldBe(JsonValueKind.String);
            values["sub"].ValueKind.ShouldBe(JsonValueKind.String);
            values["active"].ValueKind.ShouldBe(JsonValueKind.True);
            values["scope"].ValueKind.ShouldBe(JsonValueKind.String);

            values["scope"].ToString().ShouldBe("api1");
        }

        [Fact]
        [Trait("Category", Category)]
        public async Task Response_data_should_be_valid_using_multiple_scopes_multiple_audiences()
        {
            var tokenResponse = await _client.RequestClientCredentialsTokenAsync(new ClientCredentialsTokenRequest
            {
                Address = TokenEndpoint,
                ClientId = "client1",
                ClientSecret = "secret",

                Scope = "api2 api3-a api3-b",
            }, cancellationToken: TestContext.Current.CancellationToken);

            tokenResponse.IsError.ShouldBeFalse();

            var introspectionResponse = await _client.IntrospectTokenAsync(new TokenIntrospectionRequest
            {
                Address = IntrospectionEndpoint,
                ClientId = "api3",
                ClientSecret = "secret",

                Token = tokenResponse.AccessToken
            }, cancellationToken: TestContext.Current.CancellationToken);

            var values = introspectionResponse.Json.Value.ToObject<Dictionary<string, JsonElement>>();

            values["aud"].ValueKind.ShouldBe(JsonValueKind.Array);

            var audiences = values["aud"].EnumerateArray();
            foreach (var aud in audiences)
            {
                aud.ValueKind.ShouldBe(JsonValueKind.String);
            }

            values["iss"].ValueKind.ShouldBe(JsonValueKind.String);
            values["nbf"].ValueKind.ShouldBe(JsonValueKind.Number);
            values["exp"].ValueKind.ShouldBe(JsonValueKind.Number);
            values["client_id"].ValueKind.ShouldBe(JsonValueKind.String);
            values["active"].ValueKind.ShouldBe(JsonValueKind.True);
            values["scope"].ValueKind.ShouldBe(JsonValueKind.String);

            var scopes = values["scope"].ToString();
            scopes.ShouldBe("api3-a api3-b");
        }

        [Fact]
        [Trait("Category", Category)]
        public async Task Response_data_should_be_valid_using_multiple_scopes_single_audience()
        {
            var tokenResponse = await _client.RequestClientCredentialsTokenAsync(new ClientCredentialsTokenRequest
            {
                Address = TokenEndpoint,
                ClientId = "client1",
                ClientSecret = "secret",

                Scope = "api3-a api3-b",
            }, cancellationToken: TestContext.Current.CancellationToken);

            tokenResponse.IsError.ShouldBeFalse();

            var introspectionResponse = await _client.IntrospectTokenAsync(new TokenIntrospectionRequest
            {
                Address = IntrospectionEndpoint,
                ClientId = "api3",
                ClientSecret = "secret",

                Token = tokenResponse.AccessToken
            }, cancellationToken: TestContext.Current.CancellationToken);

            var values = introspectionResponse.Json.Value.ToObject<Dictionary<string, JsonElement>>();

            values["aud"].ValueKind.ShouldBe(JsonValueKind.String);
            values["iss"].ValueKind.ShouldBe(JsonValueKind.String); 
            values["nbf"].ValueKind.ShouldBe(JsonValueKind.Number); 
            values["exp"].ValueKind.ShouldBe(JsonValueKind.Number); 
            values["client_id"].ValueKind.ShouldBe(JsonValueKind.String); 
            values["active"].ValueKind.ShouldBe(JsonValueKind.True); 
            values["scope"].ValueKind.ShouldBe(JsonValueKind.String);

            var scopes = values["scope"].ToString();
            scopes.ShouldBe("api3-a api3-b");
        }

        [Fact]
        [Trait("Category", Category)]
        public async Task Token_with_many_scopes_but_api_should_only_see_its_own_scopes()
        {
            var tokenResponse = await _client.RequestClientCredentialsTokenAsync(new ClientCredentialsTokenRequest
            {
                Address = TokenEndpoint,
                ClientId = "client3",
                ClientSecret = "secret",

                Scope = "api1 api2 api3-a",
            }, cancellationToken: TestContext.Current.CancellationToken);

            tokenResponse.IsError.ShouldBeFalse();

            var introspectionResponse = await _client.IntrospectTokenAsync(new TokenIntrospectionRequest
            {
                Address = IntrospectionEndpoint,
                ClientId = "api3",
                ClientSecret = "secret",

                Token = tokenResponse.AccessToken
            }, cancellationToken: TestContext.Current.CancellationToken);

            introspectionResponse.IsActive.ShouldBeTrue();
            introspectionResponse.IsError.ShouldBeFalse();

            var scopes = from c in introspectionResponse.Claims
                         where c.Type == "scope"
                         select c.Value;

            scopes.Count().ShouldBe(1);
            scopes.First().ShouldBe("api3-a");
        }

        [Fact]
        [Trait("Category", Category)]
        public async Task Valid_token_with_valid_multiple_scopes()
        {
            var tokenResponse = await _client.RequestClientCredentialsTokenAsync(new ClientCredentialsTokenRequest
            {
                Address = TokenEndpoint,
                ClientId = "client1",
                ClientSecret = "secret",

                Scope = "api1 api2",
            }, cancellationToken: TestContext.Current.CancellationToken);

            var introspectionResponse = await _client.IntrospectTokenAsync(new TokenIntrospectionRequest
            {
                Address = IntrospectionEndpoint,
                ClientId = "api1",
                ClientSecret = "secret",

                Token = tokenResponse.AccessToken
            }, cancellationToken: TestContext.Current.CancellationToken);

            introspectionResponse.IsActive.ShouldBe(true);
            introspectionResponse.IsError.ShouldBe(false);

            var scopes = from c in introspectionResponse.Claims
                         where c.Type == "scope"
                         select c;

            scopes.Count().ShouldBe(1);
            scopes.First().Value.ShouldBe("api1");
        }

        [Fact]
        [Trait("Category", Category)]
        public async Task Valid_token_with_invalid_scopes_should_fail()
        {
            var tokenResponse = await _client.RequestClientCredentialsTokenAsync(new ClientCredentialsTokenRequest
            {
                Address = TokenEndpoint,
                ClientId = "client1",
                ClientSecret = "secret",

                Scope = "api1",
            }, cancellationToken: TestContext.Current.CancellationToken);

            var introspectionResponse = await _client.IntrospectTokenAsync(new TokenIntrospectionRequest
            {
                Address = IntrospectionEndpoint,
                ClientId = "api2",
                ClientSecret = "secret",

                Token = tokenResponse.AccessToken
            }, cancellationToken: TestContext.Current.CancellationToken);

            introspectionResponse.IsActive.ShouldBe(false);
            introspectionResponse.IsError.ShouldBe(false);
        }
    }
}