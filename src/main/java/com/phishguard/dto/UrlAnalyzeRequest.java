package com.phishguard.dto;

import jakarta.validation.constraints.NotBlank;

public record UrlAnalyzeRequest(
        @NotBlank(message = "url is required") String url
) {}
