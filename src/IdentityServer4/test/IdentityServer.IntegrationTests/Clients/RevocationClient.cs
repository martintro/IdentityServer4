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
using Microsoft.Extensions.Hosting;
using Xunit;

namespace IdentityServer.IntegrationTests.Clients
{
    public class RevocationClient
    {
        private const string TokenEndpoint = "https://server/connect/token";
        private const string RevocationEndpoint = "https://server/connect/revocation";
        private const string IntrospectionEndpoint = "https://server/connect/introspect";

        private readonly HttpClient _client;

        public RevocationClient()
        {
            var host = new HostBuilder()
                .ConfigureWebHost(builder => builder
                    .UseTestServer()
                    .UseStartup<Startup>())
                .Start();
            var server = host.GetTestServer();

            _client = server.CreateClient();
        }

        [Fact]
        public async Task Revoking_reference_token_should_invalidate_token()
        {
            // request acccess token
            var response = await _client.RequestPasswordTokenAsync(new PasswordTokenRequest
            {
                Address = TokenEndpoint,
                ClientId = "roclient.reference",
                ClientSecret = "secret",

                Scope = "api1",
                UserName = "bob",
                Password = "bob"
            }, cancellationToken: TestContext.Current.CancellationToken);

            response.IsError.ShouldBeFalse();

            // introspect - should be active
            var introspectionResponse = await _client.IntrospectTokenAsync(new TokenIntrospectionRequest
            {
                Address = IntrospectionEndpoint,
                ClientId = "api",
                ClientSecret = "secret",

                Token = response.AccessToken
            }, cancellationToken: TestContext.Current.CancellationToken);

            introspectionResponse.IsActive.ShouldBe(true);

            // revoke access token
            var revocationResponse = await _client.RevokeTokenAsync(new TokenRevocationRequest
            {
                Address = RevocationEndpoint,
                ClientId = "roclient.reference",
                ClientSecret = "secret",

                Token = response.AccessToken
            }, cancellationToken: TestContext.Current.CancellationToken);

            // introspect - should be inactive
            introspectionResponse = await _client.IntrospectTokenAsync(new TokenIntrospectionRequest
            {
                Address = IntrospectionEndpoint,
                ClientId = "api",
                ClientSecret = "secret",

                Token = response.AccessToken
            }, cancellationToken: TestContext.Current.CancellationToken);

            introspectionResponse.IsActive.ShouldBe(false);
        }
    }
}