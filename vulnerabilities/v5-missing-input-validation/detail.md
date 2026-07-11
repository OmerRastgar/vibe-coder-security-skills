# V5 — Missing Input Validation

Failing to deeply validate or cast incoming user inputs (the "Happy Path" assumption) leads to systemic abuse. Targets include type bypassing in JSON bodies, extension spoofing in file uploads, pagination abuse via URL parameters, and webhook signature spoofing.

Targets: JSON payloads & bodies, file & media uploads, URL params & queries, forms & headers.
