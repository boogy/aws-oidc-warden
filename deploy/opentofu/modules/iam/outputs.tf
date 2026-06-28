output "role_arn" {
  description = "Lambda execution role ARN."
  value       = aws_iam_role.this.arn
}

output "role_name" {
  description = "Lambda execution role name."
  value       = aws_iam_role.this.name
}
