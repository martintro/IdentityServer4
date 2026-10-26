// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Copyright (c) 2026 Martin Troedsson. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using Shouldly;
using Duende.IdentityModel;
using IdentityServer.UnitTests.Common;
using IdentityServer4.Configuration;
using IdentityServer4.Extensions;
using IdentityServer4.Models;
using Microsoft.AspNetCore.Authentication;
using Xunit;

namespace IdentityServer.UnitTests.Extensions
{
    public class JwtPayloadCreationTests
    {
        private Token _token;
        
        public JwtPayloadCreationTests()
        {
            var claims = new List<Claim>
            {
                new Claim(JwtClaimTypes.Scope, "scope1"),
                new Claim(JwtClaimTypes.Scope, "scope2"),
                new Claim(JwtClaimTypes.Scope, "scope3"),
            };
            
            _token = new Token(OidcConstants.TokenTypes.AccessToken)
            {
                CreationTime = DateTime.UtcNow,
                Issuer = "issuer",
                Lifetime = 60,
                Claims = claims.Distinct(new ClaimComparer()).ToList(),
                ClientId = "client"
            };
        }
        
        [Fact]
        public void Should_create_scopes_as_array_by_default()
        {
            var options = new IdentityServerOptions();
            var payload = _token.CreateJwtPayload(new SystemClock(), options, TestLogger.Create<JwtPayloadCreationTests>());

            payload.ShouldNotBeNull();
            var scopes = payload.Claims.Where(c => c.Type == JwtClaimTypes.Scope).ToArray();
            scopes.Count().ShouldBe(3);
            scopes[0].Value.ShouldBe("scope1");
            scopes[1].Value.ShouldBe("scope2");
            scopes[2].Value.ShouldBe("scope3");
        }
        
        [Fact]
        public void Should_create_scopes_as_string()
        {
            var options = new IdentityServerOptions
            {
                EmitScopesAsSpaceDelimitedStringInJwt = true
            };
            
            var payload = _token.CreateJwtPayload(new SystemClock(), options, TestLogger.Create<JwtPayloadCreationTests>());

            payload.ShouldNotBeNull();
            var scopes = payload.Claims.Where(c => c.Type == JwtClaimTypes.Scope).ToList();
            scopes.Count().ShouldBe(1);
            scopes.First().Value.ShouldBe("scope1 scope2 scope3");
        }
    }
}
