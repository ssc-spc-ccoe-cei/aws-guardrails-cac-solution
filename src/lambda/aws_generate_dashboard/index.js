/**
* Lambda handler to generate compliance dashboards from CSV evidence files.
* Triggered by S3 ObjectCreated events on gc-fedclient bucket.
* Outputs one detailed HTML dashboard to the same source/report S3 bucket.
*/

const fs = require('fs');
const path = require('path');
const { parse } = require('csv-parse/sync');
const Handlebars = require('handlebars');
const {
    S3Client,
    GetObjectCommand,
    PutObjectCommand,
} = require('@aws-sdk/client-s3');
const { DataProcessor } = require('./lib/dataProcessor');

const s3 = new S3Client({});

// Helper: buffer a Node.js Readable stream (v3 returns streams for GetObject.Body)
async function streamToString(stream) {
    const chunks = [];
    for await (const chunk of stream) {
        chunks.push(typeof chunk === 'string' ? Buffer.from(chunk) : chunk);
    }
    return Buffer.concat(chunks).toString('utf-8');
}

const ORG_NAME = process.env.ORG_NAME || 'Unknown Org';
const CAC_VERSION = process.env.CAC_VERSION || 'v2.0';

// Load Handlebars templates
const templateDir = path.join(__dirname, 'templates');
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
        const detailedData = processor.generateDetailedData();

        const detailedHtml = detailedTemplate({
            orgName,
            cacVersion,
            reportDate,
            ...detailedData,
        });

        const dashboardKey = 'dashboards/latest.html';

        await s3.send(new PutObjectCommand({
            Bucket: sourceBucket,
            Key: dashboardKey,
            Body: detailedHtml,
            ContentType: 'text/html',
        }));

        console.log(`Written s3://${sourceBucket}/${dashboardKey}`);

        return {
            status: 'success',
            dashboardKey,
        };
    } catch (error) {
        console.error('Error:', error);
        throw error;
    }
};

