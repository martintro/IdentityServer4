// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityServer4.EntityFramework.Entities;

namespace IdentityServer4.EntityFramework.Mappers
{
    /// <summary>
    /// Extension methods to map to/from entity/model for scopes.
    /// </summary>
    public static class ScopeMappers
    {
        /// <summary>
        /// Maps an entity to a model.
        /// </summary>
        /// <param name="entity">The entity.</param>
        /// <returns></returns>
        public static Models.ApiScope ToModel(this ApiScope entity)
        {
            if (entity == null) return null;

            return new Models.ApiScope
            {
                Enabled = entity.Enabled,
                Name = entity.Name,
                DisplayName = entity.DisplayName,
                Description = entity.Description,
                ShowInDiscoveryDocument = entity.ShowInDiscoveryDocument,
                UserClaims = entity.UserClaims.MapToHashSet(uc => uc.Type),
                Properties = entity.Properties.ToPropertyDictionary(),
                Required = entity.Required,
                Emphasize = entity.Emphasize
            };
        }

        /// <summary>
        /// Maps a model to an entity.
        /// </summary>
        /// <param name="model">The model.</param>
        /// <returns></returns>
        public static ApiScope ToEntity(this Models.ApiScope model)
        {
            if (model == null) return null;

            return new ApiScope
            {
                Enabled = model.Enabled,
                Name = model.Name,
                DisplayName = model.DisplayName,
                Description = model.Description,
                ShowInDiscoveryDocument = model.ShowInDiscoveryDocument,
                UserClaims = model.UserClaims.MapToList(uc => new ApiScopeClaim
                {
                    Type = uc
                }),
                Properties = model.Properties.ToPropertyEntities<ApiScopeProperty>(),
                Required = model.Required,
                Emphasize = model.Emphasize
            };
        }
    }
}
