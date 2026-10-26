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
    public class ClientCredentialsandResourceOwnerClient
    {
        private const string TokenEndpoint = "https://server/connect/token";

        private readonly HttpClient _client;

        public ClientCredentialsandResourceOwnerClient()
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
        public async Task Resource_scope_should_be_requestable_via_client_credentials()
        {
            var response = await _client.RequestClientCredentialsTokenAsync(new ClientCredentialsTokenRequest
            {
                Address = TokenEndpoint,
                ClientId = "client.and.ro",
                ClientSecret = "secret",
                Scope = "api1"
            }, cancellationToken: TestContext.Current.CancellationToken);

            response.IsError.ShouldBe(false);
        }

        [Fact]
        public async Task Openid_scope_should_not_be_requestable_via_client_credentials()
        {
            var response = await _client.RequestClientCredentialsTokenAsync(new ClientCredentialsTokenRequest
            {
                Address = TokenEndpoint,
                ClientId = "client.and.ro",
                ClientSecret = "secret",
                Scope = "openid api1"
            }, cancellationToken: TestContext.Current.CancellationToken);

            response.IsError.ShouldBe(true);
        }

        [Fact]
        public async Task Openid_scope_should_be_requestable_via_password()
        {
            var response = await _client.RequestPasswordTokenAsync(new PasswordTokenRequest
            {
                Address = TokenEndpoint,
                ClientId = "client.and.ro",
                ClientSecret = "secret",
                Scope = "openid",

                UserName = "bob",
                Password = "bob"
            }, cancellationToken: TestContext.Current.CancellationToken);

            response.IsError.ShouldBe(false);
        }

        [Fact]
        public async Task Openid_and_resource_scope_should_be_requestable_via_password()
        {
            var response = await _client.RequestPasswordTokenAsync(new PasswordTokenRequest
            {
                Address = TokenEndpoint,
                ClientId = "client.and.ro",
                ClientSecret = "secret",
                Scope = "openid api1",

                UserName = "bob",
                Password = "bob"
            }, cancellationToken: TestContext.Current.CancellationToken);

            response.IsError.ShouldBe(false);
        }
    }
}