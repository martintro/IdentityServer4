// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Copyright (c) 2025 Martin Troedsson. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Duende.IdentityModel;

namespace IdentityServer4.Extensions
{
    /// <summary>
    /// Extensions methods for X509Certificate2
    /// </summary>
    public static class X509CertificateExtensions
    {
        /// <summary>
        /// Create the value of a thumbprint-based cnf claim
        /// </summary>
        /// <param name="certificate"></param>
        /// <returns></returns>
        public static string CreateThumbprintCnf(this X509Certificate2 certificate)
        {
            var hash = certificate.GetCertHash(HashAlgorithmName.SHA256);
                            
            var values = new Dictionary<string, string>
            {
                { "x5t#S256", Base64Url.Encode(hash) }
            };

            return JsonSerializer.Serialize(values);
        }
    }
}