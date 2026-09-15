// Failure Domain Registry — shared library export decoration.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.

#ifndef FAILURE_DOMAIN_REGISTRY_EXPORT_HPP
#define FAILURE_DOMAIN_REGISTRY_EXPORT_HPP

// The library is static by default, so the decoration is empty unless a shared
// build was requested. FAILURE_DOMAIN_REGISTRY_BUILD_SHARED is defined by the
// build when this project compiles the library itself;
// FAILURE_DOMAIN_REGISTRY_USE_SHARED is propagated to consumers.
#if defined(_WIN32) && defined(FAILURE_DOMAIN_REGISTRY_BUILD_SHARED)
#define FAILURE_DOMAIN_REGISTRY_API __declspec(dllexport)
#elif defined(_WIN32) && defined(FAILURE_DOMAIN_REGISTRY_USE_SHARED)
#define FAILURE_DOMAIN_REGISTRY_API __declspec(dllimport)
#elif defined(__GNUC__) && defined(FAILURE_DOMAIN_REGISTRY_BUILD_SHARED)
#define FAILURE_DOMAIN_REGISTRY_API __attribute__((visibility("default")))
#else
#define FAILURE_DOMAIN_REGISTRY_API
#endif

/// Short alias used throughout the headers.
#define FDR_API FAILURE_DOMAIN_REGISTRY_API

#endif // FAILURE_DOMAIN_REGISTRY_EXPORT_HPP
