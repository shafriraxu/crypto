// Copyright © 2023 Niklas Siemer
//
// This file is part of qFALL-crypto.
//
// qFALL-crypto is free software: you can redistribute it and/or modify it under
// the terms of the Mozilla Public License Version 2.0 as published by the
// Mozilla Foundation. See <https://mozilla.org/en-US/MPL/2.0/>.

//! This module collects different distributions and implementations to draw
//! samples according to a specified distribution.

pub mod binomial;
pub mod discrete_gauss;
pub mod uniform;