resource "aws_kms_key" "pay" {
  customer_master_key_spec = "RSA_2048"
}
