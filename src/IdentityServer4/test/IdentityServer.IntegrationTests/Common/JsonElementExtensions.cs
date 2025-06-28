// Copyright (c) Martin Troedsson. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System.Text.Json;

namespace IdentityServer.IntegrationTests.Common
{
    public static class JsonElementExtensions
    {
        public static T ToObject<T>(this JsonElement jsonElement)
        {
            return jsonElement.Deserialize<T>();
        }
    }
}
