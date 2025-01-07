# CVSS Vector Generator and Analyzer

A powerful web application for analyzing and processing CVSS (Common Vulnerability Scoring System) vectors from Excel files. This tool helps security professionals and analysts quickly process multiple CVSS vectors, calculate scores, and generate comprehensive reports.

## Features

### 1. Excel File Processing
- Upload Excel files containing CVSS vectors
- Intelligent vector detection from any column
- Support for multiple sheets and formats
- Bulk processing capabilities

### 2. CVSS Calculation
- Base Score calculation
- Temporal Score analysis
- Environmental Score computation
- Impact Score breakdown
- Severity level determination

### 3. Comprehensive Analysis
- Detailed metric breakdowns
- Qualitative metric descriptions
- Impact assessments
- Severity distribution statistics

### 4. Export Capabilities
- Export results to Excel
- Detailed scoring breakdown
- Qualitative metric descriptions
- Auto-formatted columns
- Date-stamped files

### 5. User Interface
- Modern, responsive design
- Dark/Light mode support
- Real-time processing feedback
- Interactive statistics display
- Error handling and validation

## Getting Started

### Prerequisites
```bash
node >= 14.0.0
npm >= 6.0.0
```

### Installation
1. Clone the repository:
```bash
git clone https://github.com/yourusername/cvss-generator.git
cd cvss-generator
```

2. Install dependencies:
```bash
npm install
```

3. Start the development server:
```bash
npm start
```

The application will be available at `http://localhost:3000`

## Usage

### 1. Uploading Files
1. Click the "Upload Excel File" button
2. Select your Excel file containing CVSS vectors
3. Wait for the processing to complete
4. View the results in the table below

### 2. Understanding Results
- **Base Score**: The fundamental score based on intrinsic characteristics
- **Temporal Score**: Adjusts the base score for time-dependent factors
- **Environmental Score**: Customizes the score for your specific environment
- **Severity**: Overall risk level (None, Low, Medium, High, Critical)

### 3. Exporting Results
1. Process your Excel file
2. Click the download button in the "Total Vectors" card
3. Find your exported file named `cvss_results_YYYY-MM-DD.xlsx`

## CVSS Vector Format

The application supports CVSS 3.0 and 3.1 vectors in the following format:
```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
```

### Supported Metrics:

#### Base Metrics
- **AV** (Attack Vector): N, A, L, P
- **AC** (Attack Complexity): L, H
- **PR** (Privileges Required): N, L, H
- **UI** (User Interaction): N, R
- **S** (Scope): U, C
- **C** (Confidentiality): N, L, H
- **I** (Integrity): N, L, H
- **A** (Availability): N, L, H

#### Temporal Metrics
- **E** (Exploit Code Maturity): X, U, P, F, H
- **RL** (Remediation Level): X, O, T, W, U
- **RC** (Report Confidence): X, U, R, C

#### Environmental Metrics
- **CR** (Confidentiality Requirement): X, L, M, H
- **IR** (Integrity Requirement): X, L, M, H
- **AR** (Availability Requirement): X, L, M, H
- Modified Base Metrics (MAV, MAC, MPR, etc.)

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- FIRST.org for CVSS specifications
- Material-UI for the component library
- XLSX for Excel file processing

## Support

For support, please open an issue in the GitHub repository or contact the maintainers.
