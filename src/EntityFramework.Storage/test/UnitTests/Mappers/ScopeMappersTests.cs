// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Copyright (c) 2026 Martin Troedsson. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System.Linq;
using Shouldly;
using IdentityServer4.EntityFramework.Mappers;
using IdentityServer4.Models;
using Xunit;

namespace IdentityServer4.EntityFramework.UnitTests.Mappers
{
    public class ScopesMappersTests
    {
        [Fact]
        public void CanMapScope()
        {
            var model = new ApiScope();
            var mappedEntity = model.ToEntity();
            var mappedModel = mappedEntity.ToModel();

            Assert.NotNull(mappedModel);
            Assert.NotNull(mappedEntity);
        }

        [Fact]
        public void Properties_Map()
        {
            var model = new ApiScope()
            {
                Description = "description",
                DisplayName = "displayname",
                Name = "foo",
                UserClaims = { "c1", "c2" },
                Properties = {
                    { "x", "xx" },
                    { "y", "yy" },
               },
                Enabled = false
            };


            var mappedEntity = model.ToEntity();
            mappedEntity.Description.ShouldBe("description");
            mappedEntity.DisplayName.ShouldBe("displayname");
            mappedEntity.Name.ShouldBe("foo");

            mappedEntity.UserClaims.Count.ShouldBe(2);
            mappedEntity.UserClaims.Select(x => x.Type).ShouldBe(new[] { "c1", "c2" });
            mappedEntity.Properties.Count.ShouldBe(2);
            mappedEntity.Properties.ShouldContain(x => x.Key == "x" && x.Value == "xx");
            mappedEntity.Properties.ShouldContain(x => x.Key == "y" && x.Value == "yy");


            var mappedModel = mappedEntity.ToModel();

            mappedModel.Description.ShouldBe("description");
            mappedModel.DisplayName.ShouldBe("displayname");
            mappedModel.Enabled.ShouldBeFalse();
            mappedModel.Name.ShouldBe("foo");
            mappedModel.UserClaims.Count.ShouldBe(2);
            mappedModel.UserClaims.ShouldBe(new[] { "c1", "c2" });
            mappedModel.Properties.Count.ShouldBe(2);
            mappedModel.Properties["x"].ShouldBe("xx");
            mappedModel.Properties["y"].ShouldBe("yy");
        }
    }
}