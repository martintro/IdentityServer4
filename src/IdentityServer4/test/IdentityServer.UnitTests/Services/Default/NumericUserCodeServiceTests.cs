// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Copyright (c) 2026 Martin Troedsson. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System.Threading.Tasks;
using Shouldly;
using IdentityServer4.Services;
using Xunit;

namespace IdentityServer.UnitTests.Services.Default
{
    public class NumericUserCodeGeneratorTests
    {
        [Fact]
        public async Task GenerateAsync_should_return_expected_code()
        {
            var sut = new NumericUserCodeGenerator();

            var userCode = await sut.GenerateAsync();
            var userCodeInt = int.Parse(userCode);

            userCodeInt.ShouldBeGreaterThanOrEqualTo(100000000);
            userCodeInt.ShouldBeLessThanOrEqualTo(999999999);
        }
    }
}