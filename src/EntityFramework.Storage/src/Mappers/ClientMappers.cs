// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Copyright (c) 2026 Martin Troedsson. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System.Security.Claims;

namespace IdentityServer4.EntityFramework.Mappers
{
    /// <summary>
    /// Extension methods to map to/from entity/model for clients.
    /// </summary>
    public static class ClientMappers
    {
        /// <summary>
        /// Maps an entity to a model.
        /// </summary>
        /// <param name="entity">The entity.</param>
        /// <returns></returns>
        public static Models.Client ToModel(this Entities.Client entity)
        {
            if (entity == null) return null;

            var model = new Models.Client
            {
                Enabled = entity.Enabled,
                ClientId = entity.ClientId,
                ProtocolType = entity.ProtocolType,
                ClientSecrets = entity.ClientSecrets.MapToHashSet(cs => new Models.Secret
                {
                    Description = cs.Description,
                    Expiration = cs.Expiration,
                    Value = cs.Value,
                    Type = cs.Type
                }),
                RequireClientSecret = entity.RequireClientSecret,
                ClientName = entity.ClientName,
                Description = entity.Description,
                ClientUri = entity.ClientUri,
                LogoUri = entity.LogoUri,
                RequireConsent = entity.RequireConsent,
                AllowRememberConsent = entity.AllowRememberConsent,
                AllowedGrantTypes = entity.AllowedGrantTypes.MapToList(gt => gt.GrantType),
                RequirePkce = entity.RequirePkce,
                AllowPlainTextPkce = entity.AllowPlainTextPkce,
                RequireRequestObject = entity.RequireRequestObject,
                AllowAccessTokensViaBrowser = entity.AllowAccessTokensViaBrowser,
                RedirectUris = entity.RedirectUris.MapToHashSet(ru => ru.RedirectUri),
                PostLogoutRedirectUris = entity.PostLogoutRedirectUris.MapToHashSet(u => u.PostLogoutRedirectUri),
                FrontChannelLogoutUri = entity.FrontChannelLogoutUri,
                FrontChannelLogoutSessionRequired = entity.FrontChannelLogoutSessionRequired,
                BackChannelLogoutUri = entity.BackChannelLogoutUri,
                BackChannelLogoutSessionRequired = entity.BackChannelLogoutSessionRequired,
                AllowOfflineAccess = entity.AllowOfflineAccess,
                AllowedScopes = entity.AllowedScopes.MapToHashSet(s => s.Scope),
                AlwaysIncludeUserClaimsInIdToken = entity.AlwaysIncludeUserClaimsInIdToken,
                IdentityTokenLifetime = entity.IdentityTokenLifetime,
                AllowedIdentityTokenSigningAlgorithms = AllowedSigningAlgorithmsConverter.Convert(entity.AllowedIdentityTokenSigningAlgorithms),
                AccessTokenLifetime = entity.AccessTokenLifetime,
                AuthorizationCodeLifetime = entity.AuthorizationCodeLifetime,
                ConsentLifetime = entity.ConsentLifetime,
                AbsoluteRefreshTokenLifetime = entity.AbsoluteRefreshTokenLifetime,
                SlidingRefreshTokenLifetime = entity.SlidingRefreshTokenLifetime,
                RefreshTokenUsage = (Models.TokenUsage)entity.RefreshTokenUsage,
                UpdateAccessTokenClaimsOnRefresh = entity.UpdateAccessTokenClaimsOnRefresh,
                RefreshTokenExpiration = (Models.TokenExpiration)entity.RefreshTokenExpiration,
                AccessTokenType = (Models.AccessTokenType)entity.AccessTokenType,
                EnableLocalLogin = entity.EnableLocalLogin,
                IdentityProviderRestrictions = entity.IdentityProviderRestrictions.MapToHashSet(idp => idp.Provider),
                IncludeJwtId = entity.IncludeJwtId,
                Claims = entity.Claims.MapToHashSet(c => new Models.ClientClaim(c.Type, c.Value, ClaimValueTypes.String)),
                AlwaysSendClientClaims = entity.AlwaysSendClientClaims,
                ClientClaimsPrefix = entity.ClientClaimsPrefix,
                PairWiseSubjectSalt = entity.PairWiseSubjectSalt,
                UserSsoLifetime = entity.UserSsoLifetime,
                UserCodeType = entity.UserCodeType,
                DeviceCodeLifetime = entity.DeviceCodeLifetime,
                AllowedCorsOrigins = entity.AllowedCorsOrigins.MapToHashSet(co => co.Origin),
                Properties = entity.Properties.ToPropertyDictionary()
            };

            return model;
        }

        /// <summary>
        /// Maps a model to an entity.
        /// </summary>
        /// <param name="model">The model.</param>
        /// <returns></returns>
        public static Entities.Client ToEntity(this Models.Client model)
        {
            if (model == null) return null;

            return new Entities.Client
            {
                Enabled = model.Enabled,
                ClientId = model.ClientId,
                ProtocolType = model.ProtocolType,
                ClientSecrets = model.ClientSecrets.MapToList(cs => new Entities.ClientSecret
                {
                    Description = cs.Description,
                    Expiration = cs.Expiration,
                    Value = cs.Value,
                    Type = cs.Type
                }),
                RequireClientSecret = model.RequireClientSecret,
                ClientName = model.ClientName,
                Description = model.Description,
                ClientUri = model.ClientUri,
                LogoUri = model.LogoUri,
                RequireConsent = model.RequireConsent,
                AllowRememberConsent = model.AllowRememberConsent,
                AllowedGrantTypes = model.AllowedGrantTypes.MapToList(gt => new Entities.ClientGrantType 
                {
                    GrantType = gt 
                }),
                RequirePkce = model.RequirePkce,
                AllowPlainTextPkce = model.AllowPlainTextPkce,
                RequireRequestObject = model.RequireRequestObject,
                AllowAccessTokensViaBrowser = model.AllowAccessTokensViaBrowser,
                RedirectUris = model.RedirectUris.MapToList(ru => new Entities.ClientRedirectUri 
                {
                    RedirectUri = ru
                }),
                PostLogoutRedirectUris = model.PostLogoutRedirectUris.MapToList(u => new Entities.ClientPostLogoutRedirectUri 
                {
                    PostLogoutRedirectUri = u
                }),
                FrontChannelLogoutUri = model.FrontChannelLogoutUri,
                FrontChannelLogoutSessionRequired = model.FrontChannelLogoutSessionRequired,
                BackChannelLogoutUri = model.BackChannelLogoutUri,
                BackChannelLogoutSessionRequired = model.BackChannelLogoutSessionRequired,
                AllowOfflineAccess = model.AllowOfflineAccess,
                AllowedScopes = model.AllowedScopes.MapToList(s => new Entities.ClientScope
                {
                    Scope = s
                }),
                AlwaysIncludeUserClaimsInIdToken = model.AlwaysIncludeUserClaimsInIdToken,
                IdentityTokenLifetime = model.IdentityTokenLifetime,
                AllowedIdentityTokenSigningAlgorithms = AllowedSigningAlgorithmsConverter.Convert(model.AllowedIdentityTokenSigningAlgorithms),
                AccessTokenLifetime = model.AccessTokenLifetime,
                AuthorizationCodeLifetime = model.AuthorizationCodeLifetime,
                ConsentLifetime = model.ConsentLifetime,
                AbsoluteRefreshTokenLifetime = model.AbsoluteRefreshTokenLifetime,
                SlidingRefreshTokenLifetime = model.SlidingRefreshTokenLifetime,
                RefreshTokenUsage = (int)model.RefreshTokenUsage,
                UpdateAccessTokenClaimsOnRefresh = model.UpdateAccessTokenClaimsOnRefresh,
                RefreshTokenExpiration = (int)model.RefreshTokenExpiration,
                AccessTokenType = (int)model.AccessTokenType,
                EnableLocalLogin = model.EnableLocalLogin,
                IdentityProviderRestrictions = model.IdentityProviderRestrictions.MapToList(x => new Entities.ClientIdPRestriction
                {
                    Provider = x
                }),
                IncludeJwtId = model.IncludeJwtId,
                Claims = model.Claims.MapToList(c => new Entities.ClientClaim
                {
                    Type = c.Type,
                    Value = c.Value
                }),
                AlwaysSendClientClaims = model.AlwaysSendClientClaims,
                ClientClaimsPrefix = model.ClientClaimsPrefix,
                PairWiseSubjectSalt = model.PairWiseSubjectSalt,
                UserSsoLifetime = model.UserSsoLifetime,
                UserCodeType = model.UserCodeType,
                DeviceCodeLifetime = model.DeviceCodeLifetime,
                AllowedCorsOrigins = model.AllowedCorsOrigins.MapToList(co => new Entities.ClientCorsOrigin
                {
                    Origin = co
                }),
                Properties = model.Properties.ToPropertyEntities<Entities.ClientProperty>()
            };
        }
    }
}
