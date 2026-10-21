// Copyright (c) 2026 Martin Troedsson. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System;
using System.Collections.Generic;
using System.Linq;

namespace IdentityServer4.EntityFramework.Mappers
{
    internal static class MapperHelpers
    {
        public static HashSet<TDestination> MapToHashSet<TSource, TDestination>(this IEnumerable<TSource> source, Func<TSource, TDestination> map)
        {
            return source == null ? new HashSet<TDestination>() : new HashSet<TDestination>(source.Select(map));
        }

        public static List<TDestination> MapToList<TSource, TDestination>(this IEnumerable<TSource> source, Func<TSource, TDestination> map)
        {
            return source == null ? new List<TDestination>() : source.Select(map).ToList();
        }

        public static Dictionary<string, string> ToPropertyDictionary<TProperty>(this IEnumerable<TProperty> properties)
            where TProperty : Entities.Property
        {
            return properties == null ? new Dictionary<string, string>() : properties.ToDictionary(p => p.Key, p => p.Value);
        }

        public static List<TProperty> ToPropertyEntities<TProperty>(this IDictionary<string, string> properties)
            where TProperty : Entities.Property, new()
        {
            return properties.MapToList(x => new TProperty { Key = x.Key, Value = x.Value });
        }
    }
}
