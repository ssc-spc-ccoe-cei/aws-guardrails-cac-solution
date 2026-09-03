/**
* Data processing for compliance dashboard generation
*/

const CONTROL_DESCRIPTIONS = {
  gc01_check_alerts_flag_misuse: 'Alerts Flag Misuse Detection',
  gc01_check_attestation_letter: 'Attestation Letter',
  gc01_check_dedicated_admin_account: 'Dedicated Admin Accounts',
  gc01_check_federated_users_mfa: 'Federated Users MFA',
  gc01_check_iam_users_mfa: 'IAM Users MFA',
  gc01_check_mfa_digital_policy: 'MFA Digital Policy',
  gc01_check_monitoring_and_logging: 'Monitoring and Logging',
  gc01_check_root_mfa: 'Root Account MFA Enabled',
  gc02_check_group_access_configuration: 'Group Access Configuration',
  gc02_check_iam_password_policy: 'IAM Password Policy',
  gc02_check_password_protection_mechanisms: 'Password Protection Mechanisms',
  gc02_check_privileged_roles_review: 'Privileged Roles Review',
  gc03_check_endpoint_access_config: 'Endpoint Access Configuration',
  gc03_check_trusted_devices_admin_access: 'Trusted Devices Admin Access',
  gc04_check_alerts_flag_misuse: 'Alerts Flag Misuse Detection',
  gc04_check_enterprise_monitoring: 'Enterprise Monitoring Accounts',
  gc05_check_data_location: 'Data Location Restriction',
  gc06_check_encryption_at_rest_part1: 'Encryption at Rest (Part 1)',
  gc06_check_encryption_at_rest_part2: 'Encryption at Rest (Part 2)',
  gc07_check_certificate_authorities: 'Certificate Authorities',
  gc07_check_cryptographic_algorithms: 'Cryptographic Algorithms',
  gc07_check_encryption_in_transit: 'Encryption in Transit',
  gc08_check_cloud_deployment_guide: 'Cloud Deployment Guide',
  gc08_check_cloud_segmentation_design: 'Cloud Segmentation Design',
  gc08_check_target_network_architecture: 'Target Network Architecture',
  gc09_check_non_public_storage_accounts: 'Non-Public Storage Accounts',
  gc10_check_cyber_center_sensors: 'Cyber Center Sensors',
  gc11_check_monitoring_all_users: 'Monitoring All Users',
  gc11_check_monitoring_use_cases: 'Monitoring Use Cases',
  gc11_check_policy_event_logging: 'Policy Event Logging',
  gc11_check_security_contact: 'Security Contact',
  gc11_check_timezone: 'Logging Timezone',
  gc11_check_trail_logging: 'Trail Logging',
  gc12_check_private_marketplace: 'Private Marketplace Configuration',
  gc13_check_emergency_account_alerts: 'Emergency Account Alerts',
  gc13_check_emergency_account_management: 'Emergency Account Management',
  gc13_check_emergency_account_mgmt_approvals: 'Emergency Account Management Approvals',
  gc13_check_emergency_account_testing: 'Emergency Account Testing',
};

class DataProcessor {
  constructor(rows) {
    this.rows = rows;
  }

  extractGuardrailNumber(controlName) {
    const match = controlName.match(/gc(\d+)_/i);
    if (match) return match[1].padStart(2, '0');
    return '00';
  }

  getDescription(controlName) {
    return CONTROL_DESCRIPTIONS[controlName.toLowerCase()] || this.cleanControlName(controlName);
  }

  cleanControlName(controlName) {
    return controlName
      .replace(/^gc\d+_check_/i, '')
      .replace(/_/g, ' ')
      .split(' ')
      .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
      .join(' ');
  }

  mapComplianceToClass(compliance) {
    const val = compliance.toUpperCase().replace(/-/g, '_');
    if (val === 'COMPLIANT') return 'status-overall-compliant';
    if (['NON_COMPLIANT', 'NONCOMPLIANT', 'NON-COMPLIANT'].includes(val))
      return 'status-overall-noncompliant';
    return 'status-overall-pending';
  }

  mapComplianceToBadge(compliance) {
    const val = compliance.toUpperCase().replace(/-/g, '_');
    if (val === 'COMPLIANT') return { class: 'status-Compliant', text: 'Compliant' };
    if (['NON_COMPLIANT', 'NONCOMPLIANT', 'NON-COMPLIANT'].includes(val))
      return { class: 'status-NON-COMPLIANT', text: 'Non-compliant' };
    return { class: 'status-PENDING', text: 'Pending' };
  }

  aggregateStatus(compliances) {
    const upper = compliances.map((c) => c.toUpperCase().replace(/-/g, '_'));
    if (upper.some((v) => ['NON_COMPLIANT', 'NONCOMPLIANT', 'NON-COMPLIANT'].includes(v)))
      return 'NON_COMPLIANT';
    if (upper.every((v) => v === 'COMPLIANT')) return 'COMPLIANT';
    return 'PENDING';
  }

  generateSummaryData() {
    // Group by guardrail > control
    const groups = {};
    for (const row of this.rows) {
      const controlName = row.controlName?.trim() || '';
      const compliance = row.compliance?.trim() || '';
      const gn = this.extractGuardrailNumber(controlName);

      if (!groups[gn]) groups[gn] = {};
      if (!groups[gn][controlName]) groups[gn][controlName] = [];
      groups[gn][controlName].push(compliance);
    }

    // Calculate pie chart data
    const pieCounts = { 'Non-compliant': 0, Compliant: 0, Pending: 0 };
    const guardrails = [];
    const sortedGNs = Object.keys(groups).sort();

    for (const gn of sortedGNs) {
      const controls = groups[gn];
      const statuses = Object.values(controls).map((comps) => this.aggregateStatus(comps));

      let status;
      if (statuses.some((s) => s === 'NON_COMPLIANT')) status = 'Non-compliant';
      else if (statuses.every((s) => s === 'COMPLIANT')) status = 'Compliant';
      else status = 'Pending';

      pieCounts[status]++;

      // Add control rows for this guardrail
      let controlIdx = 1;
      for (const [controlName, comps] of Object.entries(controls)) {
        const agg = this.aggregateStatus(comps);
        const badge = this.mapComplianceToBadge(agg);
        const description = this.getDescription(controlName);

        guardrails.push({
          showHeader: controlIdx === 1,
          guardrailNum: gn,
          validation: String(controlIdx).padStart(2, '0'),
          controlName,
          description,
          compliance: badge.text,
          complianceClass: badge.class,
          overallClass: this.mapComplianceToClass(agg),
        });
        controlIdx++;
      }
    }

    const pieColors = {
      'Non-compliant': { fill: '#f8d7da', stroke: '#721c24' },
      Compliant: { fill: '#d4edda', stroke: '#155724' },
      Pending: { fill: '#fff3cd', stroke: '#856404' },
    };

    const total = Object.values(pieCounts).reduce((a, b) => a + b, 0);
    const legend = [];
    for (const [label, count] of Object.entries(pieCounts)) {
      if (count === 0) continue;
      const pct = Math.round((100 * count) / total);
      const color = pieColors[label];
      legend.push({ label, count, pct, ...color });
    }

    return {
      guardrails,
      pieCounts,
      pieColors,
      legend,
      totalGuardrails: total,
      guardrailNumbers: sortedGNs,
      filterCss: this.generateFilterCss(sortedGNs),
    };
  }

  generateDetailedData() {
    // Sort by guardrail, control, then non-compliant first
    const sorted = [...this.rows].sort((a, b) => {
      const gnA = this.extractGuardrailNumber(a.controlName || '');
      const gnB = this.extractGuardrailNumber(b.controlName || '');
      if (gnA !== gnB) return gnA.localeCompare(gnB);

      const cnA = a.controlName || '';
      const cnB = b.controlName || '';
      if (cnA !== cnB) return cnA.localeCompare(cnB);

      const compA = (a.compliance || '').toUpperCase();
      const compB = (b.compliance || '').toUpperCase();
      const orderA = compA.includes('NON') ? 0 : 1;
      const orderB = compB.includes('NON') ? 0 : 1;
      return orderA - orderB;
    });

    const guardrailNumbers = [...new Set(sorted.map((r) => this.extractGuardrailNumber(r.controlName || '')))].sort();

    const findings = sorted.map((row) => {
      const gn = this.extractGuardrailNumber(row.controlName || '');
      const compliance = row.compliance || '';
      const badge = this.mapComplianceToBadge(compliance);
      const description = this.getDescription(row.controlName || '');

      const message = `Account: ${row.accountId || ''}${
        row.resourceType && row.resourceType.toLowerCase() !== 'none' ? ` | Resource Type: ${row.resourceType}` : ''
      }`;

      return {
        guardrailNum: gn,
        controlName: row.controlName || '',
        description,
        compliance: badge.text,
        complianceClass: badge.class,
        overallClass: this.mapComplianceToClass(compliance),
        accountId: row.accountId || '',
        resourceType: row.resourceType || '',
        resourceArn: row.resourceArn || '',
        message,
      };
    });

    return {
      findings,
      guardrailNumbers,
      filterCss: this.generateFilterCss(guardrailNumbers),
    };
  }

  generateFilterCss(guardrailNumbers) {
    let css = '';
    for (const gn of guardrailNumbers) {
      css += `
        #filter-guardrail-${gn}:checked ~ .content-wrapper .table-section table tbody tr { display: none; }
        #filter-guardrail-${gn}:checked ~ .content-wrapper .table-section table tbody tr.guardrail-${gn} { display: table-row; }
        #filter-guardrail-${gn}:checked ~ table tbody tr { display: none; }
        #filter-guardrail-${gn}:checked ~ table tbody tr.guardrail-${gn} { display: table-row; }
      `;
    }
    return css;
  }
}

module.exports = { DataProcessor };