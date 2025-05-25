# API Response Format

This document describes the API response format for the AWS OIDC Warden service.

## Success Response

When a request is successful, the API responds with a JSON object having the following structure:

```json
{
  "success": true,
  "statusCode": 200,
  "requestId": "12258876-a981-452b-a7ae-415f8fa737b6",
  "processingMs": 254,
  "message": "Token validation successful and role assumed",
  "data": {
    "AccessKeyId": "ASIA1234567890EXAMPLE",
    "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "SessionToken": "FwoGZXIvYXdzEPH//////////wEaDKLZ3MQOJZBKxR1JDiLBARJhUlx1g09xLW+oIYHDt15IZY4...",
    "Expiration": "2023-09-29T20:31:14Z"
  }
}
```

## Error Response
p a
When an error occurs, the API responds with a JSON object having the following structure:

```json
{
  "success": false,
  "statusCode": 401,
  "requestId": "12258876-a981-452b-a7ae-415f8fa737b6",
  "processingMs": 383,
  "message": "Permission denied for the requested operation",
  "errorCode": "permission_denied",
  "errorDetails": "role not allowed for repository or doesn't meet constraints"
}
```

## Field Descriptions

| Field         | Type    | Description                                                    |
| ------------- | ------- | -------------------------------------------------------------- |
| success       | boolean | Indicates whether the request was successful                   |
| statusCode    | number  | HTTP status code                                               |
| requestId     | string  | Unique identifier for the request (useful for troubleshooting) |
| processingMs  | number  | Time taken to process the request in milliseconds              |
| message       | string  | Human-readable description of the result                       |
| data          | object  | For successful responses, contains the AWS credentials         |
| errorCode     | string  | For error responses, a machine-readable error code             |
| errorDetails  | string  | For error responses, detailed error information                |
| error_details | string  | For error responses, detailed error information                |

## Common Error Codes

| Error Code         | Description                                          | Status Code |
| ------------------ | ---------------------------------------------------- | ----------- |
| invalid_request    | Missing or invalid request parameters                | 400         |
| permission_denied  | Token doesn't have permission for the requested role | 403         |
| internal_error     | An internal server error occurred                    | 500         |
| policy_error       | Error accessing or parsing policy information        | 500         |
| assume_role_failed | Failed to assume the requested AWS role              | 500         |
