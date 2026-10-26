// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Copyright (c) 2026 Martin Troedsson. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System.Net.Http;
using System.Threading.Tasks;
using Shouldly;
using Duende.IdentityModel.Client;
using IdentityServer.IntegrationTests.Clients.Setup;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Xunit;

namespace IdentityServer.IntegrationTests.Clients
{
    public class RefreshTokenClient
    {
        private const string TokenEndpoint = "https://server/connect/token";
        private const string RevocationEndpoint = "https://server/connect/revocation";

        private readonly HttpClient _client;

        public RefreshTokenClient()
        {
            var builder = new WebHostBuilder()
                .UseStartup<Startup>();
            var server = new TestServer(builder);

            _client = server.CreateClient();
        }

        [Fact]
        public async Task Requesting_a_refresh_token_without_identity_scopes_should_return_expected_results()
        {
            var response = await _client.RequestPasswordTokenAsync(new PasswordTokenRequest
            {
                Address = TokenEndpoint,
                ClientId = "roclient",
                ClientSecret = "secret",

                Scope = "api1 offline_access",
                UserName = "bob",
                Password = "bob"
            }, cancellationToken: TestContext.Current.CancellationToken);

            response.IsError.ShouldBeFalse();
            response.ExpiresIn.ShouldBe(3600);
            response.TokenType.ShouldBe("Bearer");
            response.IdentityToken.ShouldBeNull();
            response.RefreshToken.ShouldNotBeNull();

            response = await _client.RequestRefreshTokenAsync(new RefreshTokenRequest
            {
                Address = TokenEndpoint,
                ClientId = "roclient",
                ClientSecret = "secret",

                RefreshToken = response.RefreshToken
            }, cancellationToken: TestContext.Current.CancellationToken);

            response.IsError.ShouldBeFalse();
            response.ExpiresIn.ShouldBe(3600);
            response.TokenType.ShouldBe("Bearer");
            response.IdentityToken.ShouldBeNull();
            response.RefreshToken.ShouldNotBeNull();
        }

        [Fact]
        public async Task Requesting_a_refresh_token_with_identity_scopes_should_return_expected_results()
        {
            var response = await _client.RequestPasswordTokenAsync(new PasswordTokenRequest
            {
                Address = TokenEndpoint,
                ClientId = "roclient",
                ClientSecret = "secret",

                Scope = "openid api1 offline_access",
                UserName = "bob",
                Password = "bob"
            }, cancellationToken: TestContext.Current.CancellationToken);

            response.IsError.ShouldBeFalse();
            response.ExpiresIn.ShouldBe(3600);
            response.TokenType.ShouldBe("Bearer");
            response.IdentityToken.ShouldBeNull();
            response.RefreshToken.ShouldNotBeNull();

            response = await _client.RequestRefreshTokenAsync(new RefreshTokenRequest
            {
                Address = TokenEndpoint,
                ClientId = "roclient",
                ClientSecret = "secret",

                RefreshToken = response.RefreshToken
            }, cancellationToken: TestContext.Current.CancellationToken);

            response.IsError.ShouldBeFalse();
            response.ExpiresIn.ShouldBe(3600);
            response.TokenType.ShouldBe("Bearer");
            response.IdentityToken.ShouldNotBeNull();
            response.RefreshToken.ShouldNotBeNull();
        }

        [Fact]
        public async Task Refreshing_a_refresh_token_with_reuse_should_return_same_refresh_token()
        {
            var response = await _client.RequestPasswordTokenAsync(new PasswordTokenRequest
            {
                Address = TokenEndpoint,
                ClientId = "roclient.reuse",
                ClientSecret = "secret",

                Scope = "openid api1 offline_access",
                UserName = "bob",
                Password = "bob"
            }, cancellationToken: TestContext.Current.CancellationToken);

            response.IsError.ShouldBeFalse();
            response.ExpiresIn.ShouldBe(3600);
            response.TokenType.ShouldBe("Bearer");
            response.IdentityToken.ShouldBeNull();
            response.RefreshToken.ShouldNotBeNull();

            var rt1 = response.RefreshToken;

            response = await _client.RequestRefreshTokenAsync(new RefreshTokenRequest
            {
                Address = TokenEndpoint,
                ClientId = "roclient.reuse",
                ClientSecret = "secret",

                RefreshToken = response.RefreshToken
            }, cancellationToken: TestContext.Current.CancellationToken);

            response.IsError.ShouldBeFalse();
            response.ExpiresIn.ShouldBe(3600);
            response.TokenType.ShouldBe("Bearer");
            response.IdentityToken.ShouldNotBeNull();
            response.RefreshToken.ShouldNotBeNull();

            var rt2 = response.RefreshToken;

            rt1.ShouldBe(rt2);
        }
        
        [Fact]
        public async Task Refreshing_a_refresh_token_with_one_time_only_should_return_different_refresh_token()
        {
            var response = await _client.RequestPasswordTokenAsync(new PasswordTokenRequest
            {
                Address = TokenEndpoint,
                ClientId = "roclient",
                ClientSecret = "secret",

                Scope = "openid api1 offline_access",
                UserName = "bob",
                Password = "bob"
            }, cancellationToken: TestContext.Current.CancellationToken);

            response.IsError.ShouldBeFalse();
            response.ExpiresIn.ShouldBe(3600);
            response.TokenType.ShouldBe("Bearer");
            response.IdentityToken.ShouldBeNull();
            response.RefreshToken.ShouldNotBeNull();

            var rt1 = response.RefreshToken;

            response = await _client.RequestRefreshTokenAsync(new RefreshTokenRequest
            {
                Address = TokenEndpoint,
                ClientId = "roclient",
                ClientSecret = "secret",

                RefreshToken = response.RefreshToken
            }, cancellationToken: TestContext.Current.CancellationToken);

            response.IsError.ShouldBeFalse();
            response.ExpiresIn.ShouldBe(3600);
            response.TokenType.ShouldBe("Bearer");
            response.IdentityToken.ShouldNotBeNull();
            response.RefreshToken.ShouldNotBeNull();

            var rt2 = response.RefreshToken;

            rt1.ShouldNotBe(rt2);
        }
        
        [Fact]
        public async Task Replaying_a_rotated_token_should_fail()
        {
            // request initial token
            var response = await _client.RequestPasswordTokenAsync(new PasswordTokenRequest
            {
                Address = TokenEndpoint,
                ClientId = "roclient",
                ClientSecret = "secret",

                Scope = "openid api1 offline_access",
                UserName = "bob",
                Password = "bob"
            }, cancellationToken: TestContext.Current.CancellationToken);

            response.IsError.ShouldBeFalse();
            response.ExpiresIn.ShouldBe(3600);
            response.TokenType.ShouldBe("Bearer");
            response.IdentityToken.ShouldBeNull();
            response.RefreshToken.ShouldNotBeNull();

            var rt1 = response.RefreshToken;

            // refresh token
            response = await _client.RequestRefreshTokenAsync(new RefreshTokenRequest
            {
                Address = TokenEndpoint,
                ClientId = "roclient",
                ClientSecret = "secret",

                RefreshToken = response.RefreshToken
            }, cancellationToken: TestContext.Current.CancellationToken);

            response.IsError.ShouldBeFalse();
            response.ExpiresIn.ShouldBe(3600);
            response.TokenType.ShouldBe("Bearer");
            response.IdentityToken.ShouldNotBeNull();
            response.RefreshToken.ShouldNotBeNull();
            
            // refresh token (again)
            response = await _client.RequestRefreshTokenAsync(new RefreshTokenRequest
            {
                Address = TokenEndpoint,
                ClientId = "roclient",
                ClientSecret = "secret",

                RefreshToken = rt1
            }, cancellationToken: TestContext.Current.CancellationToken);

            response.IsError.ShouldBeTrue();
            response.Error.ShouldBe("invalid_grant");
        }
        
        [Fact]
        public async Task Using_a_valid_refresh_token_should_succeed()
        {
            // request initial token
            var response = await _client.RequestPasswordTokenAsync(new PasswordTokenRequest
            {
                Address = TokenEndpoint,
                ClientId = "roclient",
                ClientSecret = "secret",

                Scope = "openid api1 offline_access",
                UserName = "bob",
                Password = "bob"
            }, cancellationToken: TestContext.Current.CancellationToken);

            response.IsError.ShouldBeFalse();
            response.ExpiresIn.ShouldBe(3600);
            response.TokenType.ShouldBe("Bearer");
            response.IdentityToken.ShouldBeNull();
            response.RefreshToken.ShouldNotBeNull();

            var rt1 = response.RefreshToken;

            // refresh token
            response = await _client.RequestRefreshTokenAsync(new RefreshTokenRequest
            {
                Address = TokenEndpoint,
                ClientId = "roclient",
                ClientSecret = "secret",

                RefreshToken = rt1
            }, cancellationToken: TestContext.Current.CancellationToken);

            response.IsError.ShouldBeFalse();
        }
        
        [Fact]
        public async Task Using_a_revoked_refresh_token_should_fail()
        {
            // request initial token
            var response = await _client.RequestPasswordTokenAsync(new PasswordTokenRequest
            {
                Address = TokenEndpoint,
                ClientId = "roclient",
                ClientSecret = "secret",

                Scope = "openid api1 offline_access",
                UserName = "bob",
                Password = "bob"
            }, cancellationToken: TestContext.Current.CancellationToken);

            response.IsError.ShouldBeFalse();
            response.ExpiresIn.ShouldBe(3600);
            response.TokenType.ShouldBe("Bearer");
            response.IdentityToken.ShouldBeNull();
            response.RefreshToken.ShouldNotBeNull();

            var rt1 = response.RefreshToken;

            // revoke refresh token
            var revocationResponse = await _client.RevokeTokenAsync(new TokenRevocationRequest
            {
                Address = RevocationEndpoint,

                ClientId = "roclient",
                ClientSecret = "secret",

                Token = rt1,
                TokenTypeHint = "refresh_token"
            }, cancellationToken: TestContext.Current.CancellationToken);

            revocationResponse.IsError.ShouldBe(false);
            
            // refresh token
            response = await _client.RequestRefreshTokenAsync(new RefreshTokenRequest
            {
                Address = TokenEndpoint,
                ClientId = "roclient",
                ClientSecret = "secret",

                RefreshToken = rt1
            }, cancellationToken: TestContext.Current.CancellationToken);

            response.IsError.ShouldBeTrue();
            response.Error.ShouldBe("invalid_grant");
        }
    }
}