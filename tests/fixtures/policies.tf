resource "aws_iam_policy" "uploads" {
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid = "ReadUploads"
      Effect = "Allow"
      Action = "s3:GetObject"
      Resource = "arn:aws:s3:::${var.bucket}/$${aws:username}/*"
    }]
  })
}
data "aws_iam_policy_document" "delete" {
  statement {
    effect = "Deny"
    actions = ["s3:DeleteObject"]
    resources = ["arn:aws:s3:::example-uploads/*"]
    condition {
      test = "IpAddress"
      variable = "aws:SourceIp"
      values = ["192.0.2.0/24"]
    }
  }
}

data "aws_iam_policy_document" "home" {
  statement {
    actions = ["s3:GetObject"]
    resources = ["arn:aws:s3:::example-uploads/&{aws:username}/*"]
  }
}
resource "aws_iam_policy" "literal" {
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = "s3:GetObject"
      Resource = "arn:aws:s3:::example-uploads/*"
      Condition = {StringEquals = {"s3:prefix" = "$${*}"}}
    }]
  })
}
