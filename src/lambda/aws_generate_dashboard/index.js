/**
* Lambda handler to generate compliance dashboards from CSV evidence files.
* Triggered by S3 ObjectCreated events on gc-fedclient bucket.
* Outputs summary and detailed HTML to dashboard S3 bucket.
*/

const fs = require('fs');
const path = require('path');
const { parse } = require('csv-parse/sync');
const Handlebars = require('handlebars');
const {
  S3Client,
  GetObjectCommand,
  PutObjectCommand,
  CopyObjectCommand,
} = require('@aws-sdk/client-s3');
const { DataProcessor } = require('./lib/dataProcessor');
const { ChartGenerator } = require('./lib/chartGenerator');

const s3 = new S3Client({});

// Helper: buffer a Node.js Readable stream (v3 returns streams for GetObject.Body)
async function streamToString(stream) {
  const chunks = [];
  for await (const chunk of stream) {
    chunks.push(typeof chunk === 'string' ? Buffer.from(chunk) : chunk);
  }
  return Buffer.concat(chunks).toString('utf-8');
}

const DASHBOARD_BUCKET = process.env.DASHBOARD_BUCKET || 'gc-fedclient-dashboard-local';
const ORG_NAME = process.env.ORG_NAME || 'Unknown Org';
const CAC_VERSION = process.env.CAC_VERSION || 'v2.0';

// Load Handlebars templates
const templateDir = path.join(__dirname, 'templates');
const summaryTemplate = Handlebars.compile(
  fs.readFileSync(path.join(templateDir, 'summary.hbs'), 'utf8')
);
const detailedTemplate = Handlebars.compile(
  fs.readFileSync(path.join(templateDir, 'detailed.hbs'), 'utf8')
);

// Register Handlebars helpers
Handlebars.registerHelper('eq', (a, b) => a === b);
Handlebars.registerHelper('ne', (a, b) => a !== b);
Handlebars.registerHelper('uppercase', (str) => str.toUpperCase());
Handlebars.registerHelper('zfill', (num, len) => String(num).padStart(len, '0'));

/**
* Main Lambda handler
*/
exports.lambda_handler = async (event, context) => {
  try {
    const record = event.Records[0].s3;
    const sourceBucket = record.bucket.name;
    const key = record.object.key;

    console.log(`Triggered by s3://${sourceBucket}/${key}`);

    // Skip internal files
    if (key.startsWith('chunks/') || key.startsWith('state/') || !key.toLowerCase().endsWith('.csv')) {
      console.log(`Skipping key: ${key}`);
      return { status: 'skipped' };
    }

    // Fetch CSV from S3
    const csvObject = await s3.send(
      new GetObjectCommand({ Bucket: sourceBucket, Key: key })
    );
    const csvContent = await streamToString(csvObject.Body);

    // Parse CSV
    const rows = parse(csvContent, {
      columns: true,
      skip_empty_lines: true,
    });

    console.log(`Read ${rows.length} data rows from CSV`);

    if (rows.length === 0) {
      console.warn('CSV contained no data rows');
      return { status: 'empty' };
    }

    // Extract org/version from first row
    const first = rows[0];
    const orgName = first.organizationName?.trim() || ORG_NAME;
    const cacVersion = first.cacVersion?.trim() || CAC_VERSION;
    const reportDate = new Date().toISOString().split('T')[0];

    // Process data
    const processor = new DataProcessor(rows);
    const summaryData = processor.generateSummaryData();
    const detailedData = processor.generateDetailedData();

    // Generate charts
    const chartGen = new ChartGenerator();
    const pieSvg = chartGen.generatePieSvg(summaryData.pieCounts, summaryData.pieColors);

    // Render templates
    const summaryHtml = summaryTemplate({
      orgName,
      cacVersion,
      reportDate,
      ...summaryData,
      pieSvg,
    });

    const detailedHtml = detailedTemplate({
      orgName,
      cacVersion,
      reportDate,
      ...detailedData,
    });

    // Derive output keys
    const stem = key.replace(/\.csv$/, '');
    const summaryKey = `${stem}_summary.html`;
    const detailedKey = `${stem}_detailed.html`;

    // Upload to dashboard bucket
    await Promise.all([
      s3.send(new PutObjectCommand({
        Bucket: DASHBOARD_BUCKET,
        Key: summaryKey,
        Body: summaryHtml,
        ContentType: 'text/html',
      })),
      s3.send(new PutObjectCommand({
        Bucket: DASHBOARD_BUCKET,
        Key: detailedKey,
        Body: detailedHtml,
        ContentType: 'text/html',
      })),
    ]);

    console.log(`Written s3://${DASHBOARD_BUCKET}/${summaryKey}`);
    console.log(`Written s3://${DASHBOARD_BUCKET}/${detailedKey}`);

    // Update "latest" symlinks
    await Promise.all([
      s3.send(new CopyObjectCommand({
        Bucket: DASHBOARD_BUCKET,
        CopySource: `/${DASHBOARD_BUCKET}/${encodeURIComponent(summaryKey)}`,
        Key: 'latest_summary.html',
        ContentType: 'text/html',
        MetadataDirective: 'REPLACE',
      })),
      s3.send(new CopyObjectCommand({
        Bucket: DASHBOARD_BUCKET,
        CopySource: `/${DASHBOARD_BUCKET}/${encodeURIComponent(detailedKey)}`,
        Key: 'latest_detailed.html',
        ContentType: 'text/html',
        MetadataDirective: 'REPLACE',
      })),
    ]);

    return {
      status: 'success',
      summaryKey,
      detailedKey,
    };
  } catch (error) {
    console.error('Error:', error);
    throw error;
  }
};

