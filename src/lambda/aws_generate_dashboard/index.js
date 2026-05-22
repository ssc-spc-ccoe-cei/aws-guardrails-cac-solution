/**
* Lambda handler to generate compliance dashboards from CSV evidence files.
* Triggered by S3 ObjectCreated events on gc-fedclient bucket.
* Outputs summary and detailed HTML to dashboard S3 bucket.
*/

const AWS = require('aws-sdk');
const fs = require('fs');
const path = require('path');
const { parse } = require('csv-parse/sync');
const Handlebars = require('handlebars');
const { DataProcessor } = require('./lib/dataProcessor');
const { ChartGenerator } = require('./lib/chartGenerator');

const s3 = new AWS.S3();

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
    const csvObject = await s3.getObject({ Bucket: sourceBucket, Key: key }).promise();
    const csvContent = csvObject.Body.toString('utf-8');

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
      s3.putObject({
        Bucket: DASHBOARD_BUCKET,
        Key: summaryKey,
        Body: summaryHtml,
        ContentType: 'text/html',
      }).promise(),
      s3.putObject({
        Bucket: DASHBOARD_BUCKET,
        Key: detailedKey,
        Body: detailedHtml,
        ContentType: 'text/html',
      }).promise(),
    ]);

    console.log(`Written s3://${DASHBOARD_BUCKET}/${summaryKey}`);
    console.log(`Written s3://${DASHBOARD_BUCKET}/${detailedKey}`);

    // Update "latest" symlinks
    await Promise.all([
      s3.copyObject({
        Bucket: DASHBOARD_BUCKET,
        CopySource: { Bucket: DASHBOARD_BUCKET, Key: summaryKey },
        Key: 'latest_summary.html',
        ContentType: 'text/html',
        MetadataDirective: 'REPLACE',
      }).promise(),
      s3.copyObject({
        Bucket: DASHBOARD_BUCKET,
        CopySource: { Bucket: DASHBOARD_BUCKET, Key: detailedKey },
        Key: 'latest_detailed.html',
        ContentType: 'text/html',
        MetadataDirective: 'REPLACE',
      }).promise(),
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

