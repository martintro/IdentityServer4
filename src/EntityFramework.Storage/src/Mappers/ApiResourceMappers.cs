// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityServer4.EntityFramework.Entities;
using System.Linq;

namespace IdentityServer4.EntityFramework.Mappers
{
    /// <summary>
    /// Extension methods to map to/from entity/model for API resources.
    /// </summary>
    public static class ApiResourceMappers
    {
        /// <summary>
        /// Maps an entity to a model.
        /// </summary>
        /// <param name="entity">The entity.</param>
        /// <returns></returns>
        public static Models.ApiResource ToModel(this ApiResource entity)
        {
            if (entity == null) return null;

            return new Models.ApiResource
            {
                Enabled = entity.Enabled,
                Name = entity.Name,
                DisplayName = entity.DisplayName,
                Description = entity.Description,
                ShowInDiscoveryDocument = entity.ShowInDiscoveryDocument,
                UserClaims = entity.UserClaims.MapToHashSet(uc => uc.Type),
                Properties = entity.Properties.ToPropertyDictionary(),
                ApiSecrets = entity.Secrets.MapToHashSet(s => new Models.Secret
                {
                    Description = s.Description,
                    Value = s.Value,
                    Expiration = s.Expiration,
                    Type = s.Type
                }),
                Scopes = entity.Scopes.MapToHashSet(s => s.Scope),
                AllowedAccessTokenSigningAlgorithms = AllowedSigningAlgorithmsConverter.Convert(entity.AllowedAccessTokenSigningAlgorithms)
            };
        }

        /// <summary>
        /// Maps a model to an entity.
        /// </summary>
        /// <param name="model">The model.</param>
        /// <returns></returns>
        public static ApiResource ToEntity(this Models.ApiResource model)
        {
            if (model == null) return null;

            return new ApiResource
            {
                Enabled = model.Enabled,
                Name = model.Name,
                DisplayName = model.DisplayName,
                Description = model.Description,
                ShowInDiscoveryDocument = model.ShowInDiscoveryDocument,
                UserClaims = model.UserClaims.MapToList(uc => new ApiResourceClaim
                {
                    Type = uc
                }),
                Properties = model.Properties.ToPropertyEntities<ApiResourceProperty>(),
                Secrets = model.ApiSecrets.MapToList(s => new ApiResourceSecret
                {
                    Description = s.Description,
                    Value = s.Value,
                    Expiration = s.Expiration,
                    Type = s.Type
                }),
                Scopes = model.Scopes.MapToList(s => new ApiResourceScope
                {
                    Scope = s
                }),
                AllowedAccessTokenSigningAlgorithms = AllowedSigningAlgorithmsConverter.Convert(model.AllowedAccessTokenSigningAlgorithms)
            };
        }
    }
}
