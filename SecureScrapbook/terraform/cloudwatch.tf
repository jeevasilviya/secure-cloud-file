# =====================================================================
# AWS CloudWatch Logs, Metric Filters & Alert Alarms
# =====================================================================

# 1. CloudWatch Log Group with 90-day retention
resource "aws_cloudwatch_log_group" "securescrapbook_audit_logs" {
  name              = "/aws/securescrapbook/security-audit"
  retention_in_days = 90

  tags = {
    Application = "SecureScrapbook"
    Purpose     = "Security-Audit-Trail"
  }
}

# 2. SNS Alert Topic for Security Notifications
resource "aws_sns_topic" "security_alerts" {
  name = "securescrapbook-security-alerts"
}

resource "aws_sns_topic_subscription" "sec_ops_email" {
  topic_arn = aws_sns_topic.security_alerts.arn
  protocol  = "email"
  endpoint  = var.security_admin_email
}

# =====================================================================
# METRIC FILTER 1: Repeated Failed Authentication Attempts
# Pattern matches HTTP 401 status, UNAUTHORIZED status or login failures
# =====================================================================
resource "aws_cloudwatch_log_metric_filter" "failed_auth_filter" {
  name           = "FailedAuthenticationFilter"
  pattern        = "{ ($.status = \"UNAUTHORIZED\") || ($.action = \"*LOGIN_FAILED*\") || ($.statusCode = 401) }"
  log_group_name = aws_cloudwatch_log_group.securescrapbook_audit_logs.name

  metric_transformation {
    name          = "FailedAuthCount"
    namespace     = "SecureScrapbook/SecurityMetrics"
    value         = "1"
    default_value = "0"
  }
}

# CloudWatch Alarm: Trigger when > 5 failed auth attempts occur within 5 minutes (Brute-Force Detection)
resource "aws_cloudwatch_metric_alarm" "failed_auth_alarm" {
  alarm_name          = "securescrapbook-brute-force-detected"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "FailedAuthCount"
  namespace           = "SecureScrapbook/SecurityMetrics"
  period              = 300 # 5 minutes
  statistic           = "Sum"
  threshold           = 5
  alarm_description   = "High volume of failed authentications detected. Possible brute-force or credential stuffing attack."
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
  ok_actions          = [aws_sns_topic.security_alerts.arn]

  treat_missing_data = "notBreaching"
}

# =====================================================================
# METRIC FILTER 2: RBAC Permission Violations & Breach Attempts
# Pattern matches HTTP 403 status or RBAC_PERMISSION_DENIED actions
# =====================================================================
resource "aws_cloudwatch_log_metric_filter" "rbac_violations_filter" {
  name           = "RBACPermissionViolationsFilter"
  pattern        = "{ ($.status = \"FORBIDDEN\") || ($.action = \"RBAC_PERMISSION_DENIED\") || ($.statusCode = 403) }"
  log_group_name = aws_cloudwatch_log_group.securescrapbook_audit_logs.name

  metric_transformation {
    name          = "RBACViolationCount"
    namespace     = "SecureScrapbook/SecurityMetrics"
    value         = "1"
    default_value = "0"
  }
}

# CloudWatch Alarm: Trigger when > 3 permission violations occur within 5 minutes (Privilege Escalation Detection)
resource "aws_cloudwatch_metric_alarm" "rbac_violation_alarm" {
  alarm_name          = "securescrapbook-privilege-escalation-detected"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "RBACViolationCount"
  namespace           = "SecureScrapbook/SecurityMetrics"
  period              = 300 # 5 minutes
  statistic           = "Sum"
  threshold           = 3
  alarm_description   = "Repeated RBAC permission violations detected. Possible unauthorized privilege escalation or lateral movement attempt."
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
  ok_actions          = [aws_sns_topic.security_alerts.arn]

  treat_missing_data = "notBreaching"
}
