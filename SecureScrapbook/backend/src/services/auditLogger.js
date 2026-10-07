/**
 * =====================================================================
 * SecureScrapbook - Auditing & CloudWatch Monitoring Service
 * =====================================================================
 * Collects structured security telemetry, persists audit events to PostgreSQL,
 * and streams JSON log streams to AWS CloudWatch Logs for SIEM alerting.
 */

const db = require('../db');

const AWS_REGION = process.env.AWS_REGION || 'us-east-1';
const LOG_GROUP_NAME = process.env.CLOUDWATCH_LOG_GROUP || '/aws/securescrapbook/security-audit';
const LOG_STREAM_NAME = process.env.CLOUDWATCH_LOG_STREAM || `api-${new Date().toISOString().slice(0, 10)}`;

// Initialize AWS CloudWatch Logs Client conditionally
let cloudWatchClient = null;
let CloudWatchLogsClient = null;
let PutLogEventsCommand = null;
let CreateLogStreamCommand = null;

try {
  const cwSdk = require('@aws-sdk/client-cloudwatch-logs');
  CloudWatchLogsClient = cwSdk.CloudWatchLogsClient;
  PutLogEventsCommand = cwSdk.PutLogEventsCommand;
  CreateLogStreamCommand = cwSdk.CreateLogStreamCommand;
  if (process.env.ENABLE_CLOUDWATCH === 'true') {
    cloudWatchClient = new CloudWatchLogsClient({ region: AWS_REGION });
  }
} catch (e) {
  // CloudWatch SDK not installed; standard fallback to structured console logging
}

let sequenceToken = null;

/**
 * Streams log event payload directly to AWS CloudWatch Logs
 * @param {object} logPayload
 */
async function streamToCloudWatch(logPayload) {
  if (!cloudWatchClient) {
    // Development fallback: Print high-visibility structured JSON to stdout
    if (process.env.NODE_ENV !== 'test') {
      console.log(`[CloudWatch Stream :: ${LOG_GROUP_NAME}]`, JSON.stringify(logPayload));
    }
    return;
  }

  try {
    const command = new PutLogEventsCommand({
      logGroupName: LOG_GROUP_NAME,
      logStreamName: LOG_STREAM_NAME,
      logEvents: [
        {
          timestamp: Date.now(),
          message: JSON.stringify(logPayload)
        }
      ],
      sequenceToken
    });

    const response = await cloudWatchClient.send(command);
    sequenceToken = response.nextSequenceToken;
  } catch (err) {
    if (err.name === 'ResourceNotFoundException') {
      try {
        await cloudWatchClient.send(new CreateLogStreamCommand({
          logGroupName: LOG_GROUP_NAME,
          logStreamName: LOG_STREAM_NAME
        }));
        // Retry once after creating log stream
        const retryCmd = new PutLogEventsCommand({
          logGroupName: LOG_GROUP_NAME,
          logStreamName: LOG_STREAM_NAME,
          logEvents: [{ timestamp: Date.now(), message: JSON.stringify(logPayload) }]
        });
        const retryRes = await cloudWatchClient.send(retryCmd);
        sequenceToken = retryRes.nextSequenceToken;
      } catch (streamErr) {
        console.error('[CloudWatch Stream Error - Creation Failed]:', streamErr.message);
      }
    } else {
      console.error('[CloudWatch Stream Error]:', err.message);
    }
  }
}

/**
 * Records a structured security audit event to PostgreSQL and AWS CloudWatch
 *
 * @param {object} params
 * @param {string|null} params.userId
 * @param {string} params.userEmail
 * @param {string} params.ipAddress
 * @param {string} params.userAgent
 * @param {string} params.action - e.g., 'AUTH_LOGIN_SUCCESS', 'RBAC_PERMISSION_DENIED', 'FILE_UPLOAD'
 * @param {string} params.resourceType - 'SCRAPBOOK', 'PAGE', 'AUTH', 'FILE'
 * @param {string} [params.resourceId]
 * @param {'SUCCESS' | 'FAILURE' | 'UNAUTHORIZED' | 'FORBIDDEN'} params.status
 * @param {string} [params.httpMethod]
 * @param {string} [params.requestUri]
 * @param {object} [params.details]
 * @param {number} [params.riskScore=0] - 0 to 100
 */
async function logAuditEvent({
  userId = null,
  userEmail = 'anonymous',
  ipAddress = '127.0.0.1',
  userAgent = 'Unknown',
  action,
  resourceType,
  resourceId = null,
  status,
  httpMethod = null,
  requestUri = null,
  details = {},
  riskScore = 0
}) {
  const timestamp = new Date().toISOString();

  const auditPayload = {
    timestamp,
    userId,
    userEmail,
    ipAddress,
    userAgent,
    action,
    resourceType,
    resourceId,
    status,
    httpMethod,
    requestUri,
    details,
    riskScore,
    environment: process.env.NODE_ENV || 'production'
  };

  // 1. Asynchronously dispatch to CloudWatch for SIEM alerting
  streamToCloudWatch(auditPayload).catch((err) => {
    console.error('[AuditLogger] CloudWatch forward error:', err.message);
  });

  // 2. Persist to PostgreSQL database for historical auditing & reporting
  try {
    const insertQuery = `
      INSERT INTO audit_logs (
        timestamp, user_id, user_email, ip_address, user_agent,
        action, resource_type, resource_id, status,
        http_method, request_uri, details, risk_score
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
    `;

    await db.query(insertQuery, [
      timestamp,
      userId,
      userEmail,
      ipAddress,
      userAgent,
      action,
      resourceType,
      resourceId,
      status,
      httpMethod,
      requestUri,
      JSON.stringify(details),
      riskScore
    ]);
  } catch (dbError) {
    // Database logging failure should not crash request processing, but must be alerted
    console.error('[AuditLogger] Database insert failure:', dbError.message);
  }
}

/**
 * Express Request Auditing Middleware
 * Intercepts incoming requests and logs responses, capturing latency and status codes.
 */
function auditMiddleware() {
  return (req, res, next) => {
    const startTime = Date.now();
    const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
    const userAgent = req.headers['user-agent'] || 'Unknown';

    // Hook response finish
    res.on('finish', () => {
      const responseTimeMs = Date.now() - startTime;
      const statusCode = res.statusCode;

      let status = 'SUCCESS';
      let riskScore = 0;

      if (statusCode === 401) {
        status = 'UNAUTHORIZED';
        riskScore = 50;
      } else if (statusCode === 403) {
        status = 'FORBIDDEN';
        riskScore = 75;
      } else if (statusCode >= 400 && statusCode < 500) {
        status = 'FAILURE';
        riskScore = 20;
      } else if (statusCode >= 500) {
        status = 'FAILURE';
        riskScore = 40;
      }

      // Stream high-level access log to CloudWatch
      streamToCloudWatch({
        type: 'HTTP_ACCESS_LOG',
        timestamp: new Date().toISOString(),
        clientIp,
        method: req.method,
        uri: req.originalUrl,
        statusCode,
        responseTimeMs,
        userEmail: req.user?.email || 'unauthenticated',
        userId: req.user?.id || null,
        userAgent,
        status,
        riskScore
      });
    });

    next();
  };
}

module.exports = {
  logAuditEvent,
  auditMiddleware,
  streamToCloudWatch
};
