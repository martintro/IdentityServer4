// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System;
using System.Collections.Generic;
using System.Linq;

namespace IdentityServer4.EntityFramework.Mappers
{
    internal static class AllowedSigningAlgorithmsConverter
    {
        public static string Convert(ICollection<string> algorithms)
        {
            if (algorithms == null || !algorithms.Any())
            {
                return null;
            }
            return algorithms.Aggregate((x, y) => $"{x},{y}");
        }

        public static ICollection<string> Convert(string algorithms)
        {
            var list = new HashSet<string>();
            if (!String.IsNullOrWhiteSpace(algorithms))
            {
                algorithms = algorithms.Trim();
                foreach (var item in algorithms.Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries).Distinct())
                {
                    list.Add(item);
                }
            }
            return list;
        }
    }
}
