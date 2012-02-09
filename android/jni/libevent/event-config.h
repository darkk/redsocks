// Copyright (c) 2009 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This file is Chromium-specific, and brings in the appropriate
// event-config.h depending on your platform.

#if defined(__APPLE__)
#include "mac/event-config.h"
#elif defined(ANDROID) // Android has to be defined before linux
#include "android/event-config.h"
#elif defined(__linux__)
#include "linux/event-config.h"
#elif defined(__FreeBSD__)
#include "freebsd/event-config.h"
#else
#error generate event-config.h for your platform
#endif
