import React, { useState } from 'react';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import {
  Container,
  Box,
  Typography,
  Paper,
  Button,
  TextField,
  IconButton,
  CircularProgress,
  Drawer,
  TableContainer,
  Table,
  TableHead,
  TableRow,
  TableCell,
  TableBody,
  Grid
} from '@mui/material';
import {
  Security as SecurityIcon,
  Upload as UploadIcon,
  Download as DownloadIcon,
  Delete as DeleteIcon,
  DarkMode as DarkModeIcon,
  LightMode as LightModeIcon,
  Info as InfoIcon,
} from '@mui/icons-material';
import { useSnackbar } from 'notistack';
import { motion } from 'framer-motion';
import * as XLSX from 'xlsx';
import { CVSSCalculator } from './utils/CVSSCalculator';
import { normalizeVector, parseVectorFromColumns, findVectorInRow } from './utils/vectorUtils';

// Statistics Card Component
const StatisticsCard = ({ results, darkMode }) => {
  const validResults = results.filter(r => r.valid);
  const averageScore = validResults.length > 0
    ? (validResults.reduce((sum, r) => sum + parseFloat(r.baseScore), 0) / validResults.length).toFixed(1)
    : 0;

  const severityCounts = {
    Critical: validResults.filter(r => r.severity === 'Critical').length,
    High: validResults.filter(r => r.severity === 'High').length,
    Medium: validResults.filter(r => r.severity === 'Medium').length,
    Low: validResults.filter(r => r.severity === 'Low').length,
    None: validResults.filter(r => r.severity === 'None').length
  };

  return (
    <Paper sx={{ 
      p: 3, 
      borderRadius: 4,
      background: darkMode 
        ? 'linear-gradient(135deg, rgba(46,49,65,0.7) 0%, rgba(46,49,65,0.3) 100%)'
        : 'white',
      backdropFilter: 'blur(10px)',
      boxShadow: '0 8px 32px 0 rgba(31, 38, 135, 0.15)'
    }}>
      <Typography variant="h6" gutterBottom fontWeight={600}>
        Statistics Overview
      </Typography>
      <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 3, mt: 2 }}>
        <Box>
          <Typography variant="subtitle2" color="text.secondary">Total Vectors</Typography>
          <Typography variant="h4">{results.length}</Typography>
        </Box>
        <Box>
          <Typography variant="subtitle2" color="text.secondary">Valid</Typography>
          <Typography variant="h4">{validResults.length}</Typography>
        </Box>
        <Box>
          <Typography variant="subtitle2" color="text.secondary">Invalid</Typography>
          <Typography variant="h4">{results.length - validResults.length}</Typography>
        </Box>
        <Box>
          <Typography variant="subtitle2" color="text.secondary">Average Base Score</Typography>
          <Typography variant="h4">{averageScore}</Typography>
        </Box>
      </Box>
      <Typography variant="subtitle1" sx={{ mt: 3, mb: 2 }} fontWeight={600}>
        Severity Distribution
      </Typography>
      <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 3 }}>
        {Object.entries(severityCounts).map(([severity, count]) => (
          <Box key={severity}>
            <Typography variant="subtitle2" color="text.secondary">{severity}</Typography>
            <Typography variant="h4">{count}</Typography>
          </Box>
        ))}
      </Box>
    </Paper>
  );
};

// Results Table Component
const ResultsTable = ({ results }) => {
  const getStatusColor = (status) => {
    switch (status) {
      case 'Valid':
        return 'success.main';
      case 'Invalid':
        return 'error.main';
      case 'Error':
        return 'warning.main';
      default:
        return 'text.primary';
    }
  };

  return (
    <TableContainer component={Paper} sx={{ mt: 2 }}>
      <Table>
        <TableHead>
          <TableRow>
            <TableCell>Sheet</TableCell>
            <TableCell>Row</TableCell>
            <TableCell>Vector</TableCell>
            <TableCell>Base Score</TableCell>
            <TableCell>Status</TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {results.map((result) => (
            <TableRow key={result.id}>
              <TableCell>{result.sheet}</TableCell>
              <TableCell>{result.row}</TableCell>
              <TableCell 
                sx={{ 
                  maxWidth: '400px', 
                  wordBreak: 'break-all',
                  color: result.status === 'Valid' ? 'success.main' : 'error.main'
                }}
              >
                {result.vector}
              </TableCell>
              <TableCell>{result.score}</TableCell>
              <TableCell>
                <Typography color={getStatusColor(result.status)}>
                  {result.status}
                </Typography>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </TableContainer>
  );
};

// Stats Display Component
const StatsDisplay = ({ stats, onExport, hasResults }) => {
  const severityColors = {
    Critical: '#cc0500',
    High: '#df3d03',
    Medium: '#f9a009',
    Low: '#ffcb0d',
    None: '#02b1f3'
  };

  return (
    <Box sx={{ mt: 2 }}>
      <Grid container spacing={2}>
        <Grid item xs={12} md={4}>
          <Paper sx={{ p: 2 }}>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <Typography variant="h6" gutterBottom>Total Vectors</Typography>
              {hasResults && (
                <IconButton 
                  color="primary" 
                  onClick={onExport}
                  title="Download Results"
                  sx={{ 
                    backgroundColor: 'primary.main',
                    color: 'white',
                    '&:hover': {
                      backgroundColor: 'primary.dark',
                    }
                  }}
                >
                  <DownloadIcon />
                </IconButton>
              )}
            </Box>
            <Typography variant="h4">{stats.totalVectors}</Typography>
            <Box sx={{ mt: 2 }}>
              <Typography color="success.main">
                Valid: {stats.validVectors}
              </Typography>
              <Typography color="error.main">
                Invalid: {stats.totalVectors - stats.validVectors}
              </Typography>
            </Box>
          </Paper>
        </Grid>
        <Grid item xs={12} md={4}>
          <Paper sx={{ p: 2 }}>
            <Typography variant="h6" gutterBottom>Average Base Score</Typography>
            <Typography variant="h4">{stats.averageScore}</Typography>
          </Paper>
        </Grid>
        <Grid item xs={12} md={4}>
          <Paper sx={{ p: 2 }}>
            <Typography variant="h6" gutterBottom>Severity Distribution</Typography>
            {Object.entries(stats.severityDistribution || {}).map(([severity, count]) => (
              <Box key={severity} sx={{ display: 'flex', alignItems: 'center', mt: 1 }}>
                <Box
                  sx={{
                    width: 16,
                    height: 16,
                    borderRadius: '50%',
                    backgroundColor: severityColors[severity],
                    mr: 1
                  }}
                />
                <Typography>
                  {severity}: {count}
                </Typography>
              </Box>
            ))}
          </Paper>
        </Grid>
      </Grid>
    </Box>
  );
};

const exportToExcel = (results) => {
  try {
    // Create workbook and worksheet
    const wb = XLSX.utils.book_new();
    
    // Convert results to worksheet format with all scores
    const wsData = results.map(row => {
      const calculator = new CVSSCalculator(row.vector);
      const scores = calculator.calculateScores() || {};
      const qualitative = calculator.getQualitativeMetrics() || {};
      const impacts = scores.impactScores || {};
      
      return {
        'Sheet': row.sheet,
        'Row': row.row,
        'Vector': row.vector,
        'Status': row.status,
        // Scores
        'Base Score': scores.baseScore || '-',
        'Temporal Score': scores.temporalScore || '-',
        'Environmental Score': scores.environmentalScore || '-',
        'Severity': scores.severity || '-',
        // Impact Scores
        'Confidentiality Impact': impacts.confidentialityImpact || '-',
        'Integrity Impact': impacts.integrityImpact || '-',
        'Availability Impact': impacts.availabilityImpact || '-',
        // Qualitative Metrics
        'Attack Vector': qualitative.attackVector || '-',
        'Attack Complexity': qualitative.attackComplexity || '-',
        'Privileges Required': qualitative.privilegesRequired || '-',
        'User Interaction': qualitative.userInteraction || '-',
        'Scope': qualitative.scope || '-',
        'Confidentiality': qualitative.confidentiality || '-',
        'Integrity': qualitative.integrity || '-',
        'Availability': qualitative.availability || '-',
        'Exploit Code Maturity': qualitative.exploitCodeMaturity || '-',
        'Remediation Level': qualitative.remediationLevel || '-',
        'Report Confidence': qualitative.reportConfidence || '-'
      };
    });

    const ws = XLSX.utils.json_to_sheet(wsData);

    // Auto-size columns
    const range = XLSX.utils.decode_range(ws['!ref']);
    const cols = [];
    for (let C = range.s.c; C <= range.e.c; ++C) {
      let maxLen = 0;
      for (let R = range.s.r; R <= range.e.r; ++R) {
        const cell = ws[XLSX.utils.encode_cell({r: R, c: C})];
        if (cell && cell.v) {
          const len = cell.v.toString().length;
          maxLen = Math.max(maxLen, len);
        }
      }
      cols[C] = { wch: maxLen + 2 };
    }
    ws['!cols'] = cols;

    // Add worksheet to workbook
    XLSX.utils.book_append_sheet(wb, ws, 'CVSS Results');

    // Generate Excel file
    const currentDate = new Date().toISOString().split('T')[0];
    XLSX.writeFile(wb, `cvss_results_${currentDate}.xlsx`);
  } catch (error) {
    console.error('Error exporting to Excel:', error);
    enqueueSnackbar('Error exporting results', { variant: 'error' });
  }
};

function App() {
  const [results, setResults] = useState([]);
  const [loading, setLoading] = useState(false);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [darkMode, setDarkMode] = useState(false);
  const [numRows, setNumRows] = useState(10);
  const [stats, setStats] = useState({
    totalVectors: 0,
    validVectors: 0,
    averageScore: 0,
    severityDistribution: {}
  });
  const { enqueueSnackbar } = useSnackbar();

  const handleFileUpload = async (event) => {
    try {
      setLoading(true);
      const file = event.target.files[0];
      
      if (!file) {
        enqueueSnackbar('No file selected', { variant: 'error' });
        return;
      }

      const reader = new FileReader();
      
      reader.onload = async (e) => {
        try {
          console.log('Processing file...');
          const data = new Uint8Array(e.target.result);
          const workbook = XLSX.read(data, { type: 'array', cellDates: true, cellNF: false, cellText: false });
          
          const allResults = [];
          let totalVectors = 0;
          let validVectors = 0;
          let totalScore = 0;
          const severityDistribution = {
            Critical: 0,
            High: 0,
            Medium: 0,
            Low: 0,
            None: 0
          };

          console.log('Sheets found:', workbook.SheetNames);

          workbook.SheetNames.forEach(sheetName => {
            console.log(`Processing sheet: ${sheetName}`);
            const worksheet = workbook.Sheets[sheetName];
            
            // Get sheet range
            const range = XLSX.utils.decode_range(worksheet['!ref'] || 'A1');
            console.log('Sheet range:', range);

            // Process each cell directly
            for (let R = range.s.r; R <= range.e.r; ++R) {
              const rowData = {};
              let hasData = false;

              for (let C = range.s.c; C <= range.e.c; ++C) {
                const cellRef = XLSX.utils.encode_cell({r: R, c: C});
                const cell = worksheet[cellRef];
                
                if (cell && cell.v !== undefined && cell.v !== null) {
                  hasData = true;
                  const value = cell.w || cell.v;
                  rowData[`Col${C + 1}`] = value.toString();
                }
              }

              if (hasData) {
                totalVectors++;
                console.log(`Processing row ${R + 1}:`, rowData);

                try {
                  let vector = findVectorInRow(rowData);
                  let score = null;
                  let severity = null;
                  let status = 'Invalid';
                  
                  if (vector) {
                    const calculator = new CVSSCalculator(vector);
                    score = calculator.calculateBaseScore();
                    
                    if (score !== null) {
                      validVectors++;
                      totalScore += score;
                      status = 'Valid';
                      severity = calculator.getSeverity(score);
                      severityDistribution[severity]++;
                    }
                  }

                  allResults.push({
                    id: totalVectors,
                    sheet: sheetName,
                    row: R + 1,
                    vector: vector || 'No valid vector found',
                    score: score !== null ? score.toFixed(1) : '-',
                    status: status,
                    severity: severity
                  });
                } catch (error) {
                  console.error('Row processing error:', error);
                  allResults.push({
                    id: totalVectors,
                    sheet: sheetName,
                    row: R + 1,
                    vector: 'Error processing row',
                    score: '-',
                    status: 'Error'
                  });
                }
              }
            }
          });

          console.log('Processing complete');
          console.log('Total vectors:', totalVectors);
          console.log('Valid vectors:', validVectors);

          setResults(allResults);
          setStats({
            totalVectors,
            validVectors,
            averageScore: validVectors > 0 ? (totalScore / validVectors).toFixed(1) : '0',
            severityDistribution
          });
          
          if (validVectors > 0) {
            enqueueSnackbar(`Found ${validVectors} valid CVSS vectors`, {
              variant: 'success'
            });
          } else {
            enqueueSnackbar('No valid CVSS vectors found', {
              variant: 'warning'
            });
          }
        } catch (error) {
          console.error('File processing error:', error);
          enqueueSnackbar('Error processing file: ' + error.message, { variant: 'error' });
        } finally {
          setLoading(false);
        }
      };

      reader.onerror = () => {
        setLoading(false);
        enqueueSnackbar('Error reading file', { variant: 'error' });
      };

      reader.readAsArrayBuffer(file);
    } catch (error) {
      setLoading(false);
      console.error('File upload error:', error);
      enqueueSnackbar('Error uploading file: ' + error.message, { variant: 'error' });
    }
  };

  const handleGenerateSample = () => {
    try {
      // Generate sample vectors
      const sampleVectors = Array.from({ length: numRows }, (_, index) => {
        const av = ['N', 'A', 'L', 'P'][Math.floor(Math.random() * 4)];
        const ac = ['L', 'H'][Math.floor(Math.random() * 2)];
        const pr = ['N', 'L', 'H'][Math.floor(Math.random() * 3)];
        const ui = ['N', 'R'][Math.floor(Math.random() * 2)];
        const s = ['U', 'C'][Math.floor(Math.random() * 2)];
        const c = ['N', 'L', 'H'][Math.floor(Math.random() * 3)];
        const impact = ['N', 'L', 'H'][Math.floor(Math.random() * 3)];
        const a = ['N', 'L', 'H'][Math.floor(Math.random() * 3)];

        return `CVSS:3.1/AV:${av}/AC:${ac}/PR:${pr}/UI:${ui}/S:${s}/C:${c}/I:${impact}/A:${a}`;
      });

      // Create workbook with vectors
      const wb = XLSX.utils.book_new();
      const ws = XLSX.utils.json_to_sheet(sampleVectors.map((vector, idx) => ({
        'ID': idx + 1,
        'CVSS Vector': vector,
        'Description': `Sample vulnerability ${idx + 1}`
      })));

      // Set column widths
      ws['!cols'] = [
        { wch: 5 },  // ID column
        { wch: 70 }, // Vector column
        { wch: 40 }  // Description column
      ];

      XLSX.utils.book_append_sheet(wb, ws, 'CVSS Vectors');

      // Save file
      XLSX.writeFile(wb, 'sample_cvss_vectors.xlsx');

      enqueueSnackbar(`Generated sample file with ${numRows} vectors`, {
        variant: 'success'
      });
    } catch (error) {
      console.error('Error generating sample:', error);
      enqueueSnackbar('Error generating sample file', { variant: 'error' });
    }
  };

  return (
    <Box 
      sx={{ 
        minHeight: '100vh',
        background: darkMode 
          ? 'linear-gradient(135deg, #1a1a1a 0%, #2d3436 100%)'
          : 'linear-gradient(135deg, #f5f7fa 0%, #e3eeff 100%)',
        transition: 'background 0.3s ease'
      }}
    >
      <Container maxWidth="xl" sx={{ py: 4 }}>
        {/* Header */}
        <Box sx={{ 
          display: 'flex', 
          justifyContent: 'space-between', 
          alignItems: 'center', 
          mb: 4,
          borderRadius: 2,
          p: 3,
          background: darkMode 
            ? 'linear-gradient(90deg, rgba(46,49,65,0.7) 0%, rgba(46,49,65,0.3) 100%)'
            : 'linear-gradient(90deg, rgba(255,255,255,0.9) 0%, rgba(255,255,255,0.5) 100%)',
          backdropFilter: 'blur(10px)',
          boxShadow: '0 8px 32px 0 rgba(31, 38, 135, 0.15)'
        }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
            <Box sx={{ 
              width: 50, 
              height: 50, 
              borderRadius: '12px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              background: 'linear-gradient(45deg, #FF6B6B 0%, #FF8E53 100%)',
              boxShadow: '0 4px 15px rgba(255, 107, 107, 0.2)'
            }}>
              <SecurityIcon sx={{ fontSize: 30, color: 'white' }} />
            </Box>
            <Box>
              <Typography variant="h4" sx={{ 
                fontWeight: 700,
                background: 'linear-gradient(45deg, #FF6B6B 0%, #FF8E53 100%)',
                WebkitBackgroundClip: 'text',
                WebkitTextFillColor: 'transparent'
              }}>
                CVSS Calculator
              </Typography>
              <Typography variant="subtitle1" color="text.secondary">
                Common Vulnerability Scoring System
              </Typography>
            </Box>
          </Box>
          <Box sx={{ display: 'flex', gap: 2 }}>
            <IconButton 
              onClick={() => setDrawerOpen(true)}
              sx={{ 
                background: darkMode ? 'rgba(255,255,255,0.05)' : 'rgba(0,0,0,0.05)',
                '&:hover': {
                  background: darkMode ? 'rgba(255,255,255,0.1)' : 'rgba(0,0,0,0.1)'
                }
              }}
            >
              <InfoIcon />
            </IconButton>
            <IconButton 
              onClick={() => setDarkMode(!darkMode)}
              sx={{ 
                background: darkMode ? 'rgba(255,255,255,0.05)' : 'rgba(0,0,0,0.05)',
                '&:hover': {
                  background: darkMode ? 'rgba(255,255,255,0.1)' : 'rgba(0,0,0,0.1)'
                }
              }}
            >
              {darkMode ? <LightModeIcon /> : <DarkModeIcon />}
            </IconButton>
          </Box>
        </Box>

        {/* Main Content */}
        <Box sx={{ display: 'flex', gap: 3, mb: 4 }}>
          {/* Sample Generator Card */}
          <Paper sx={{ 
            flex: 1,
            p: 3,
            borderRadius: 4,
            background: darkMode 
              ? 'linear-gradient(135deg, rgba(46,49,65,0.7) 0%, rgba(46,49,65,0.3) 100%)'
              : 'white',
            backdropFilter: 'blur(10px)',
            boxShadow: '0 8px 32px 0 rgba(31, 38, 135, 0.15)'
          }}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 3 }}>
              <Box sx={{ 
                width: 40,
                height: 40,
                borderRadius: '10px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                background: 'linear-gradient(45deg, #4CAF50 0%, #81C784 100%)',
                boxShadow: '0 4px 15px rgba(76, 175, 80, 0.2)'
              }}>
                <DownloadIcon sx={{ color: 'white' }} />
              </Box>
              <Typography variant="h6" fontWeight={600}>
                Generate Sample File
              </Typography>
            </Box>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 2 }}>
              <TextField
                label="Number of Rows"
                type="number"
                value={numRows}
                onChange={(e) => setNumRows(Math.max(1, Math.min(100, parseInt(e.target.value) || 1)))}
                InputProps={{ 
                  inputProps: { min: 1, max: 100 },
                  sx: { borderRadius: 2 }
                }}
                size="small"
                sx={{ minWidth: 150 }}
              />
              <Button
                variant="contained"
                onClick={handleGenerateSample}
                startIcon={<DownloadIcon />}
                sx={{
                  borderRadius: 2,
                  background: 'linear-gradient(45deg, #4CAF50 0%, #81C784 100%)',
                  boxShadow: '0 4px 15px rgba(76, 175, 80, 0.2)',
                  '&:hover': {
                    background: 'linear-gradient(45deg, #43A047 0%, #66BB6A 100%)'
                  }
                }}
              >
                Generate Excel
              </Button>
            </Box>
            <Typography variant="body2" color="text.secondary">
              Generate a sample Excel file with random CVSS vectors (max 100 rows)
            </Typography>
          </Paper>

          {/* File Upload Card */}
          <Paper sx={{ 
            flex: 1,
            p: 3,
            borderRadius: 4,
            background: darkMode 
              ? 'linear-gradient(135deg, rgba(46,49,65,0.7) 0%, rgba(46,49,65,0.3) 100%)'
              : 'white',
            backdropFilter: 'blur(10px)',
            boxShadow: '0 8px 32px 0 rgba(31, 38, 135, 0.15)'
          }}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 3 }}>
              <Box sx={{ 
                width: 40,
                height: 40,
                borderRadius: '10px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                background: 'linear-gradient(45deg, #2196F3 0%, #64B5F6 100%)',
                boxShadow: '0 4px 15px rgba(33, 150, 243, 0.2)'
              }}>
                <UploadIcon sx={{ color: 'white' }} />
              </Box>
              <Typography variant="h6" fontWeight={600}>
                Upload Excel File
              </Typography>
            </Box>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 2 }}>
              <Button
                variant="contained"
                component="label"
                startIcon={<UploadIcon />}
                disabled={loading}
                sx={{
                  borderRadius: 2,
                  background: 'linear-gradient(45deg, #2196F3 0%, #64B5F6 100%)',
                  boxShadow: '0 4px 15px rgba(33, 150, 243, 0.2)',
                  '&:hover': {
                    background: 'linear-gradient(45deg, #1E88E5 0%, #42A5F5 100%)'
                  }
                }}
              >
                Upload Excel
                <input
                  type="file"
                  hidden
                  accept=".xlsx,.xls"
                  onChange={handleFileUpload}
                />
              </Button>
              {loading && <CircularProgress size={24} />}
              {results.length > 0 && (
                <Button
                  variant="outlined"
                  onClick={() => {
                    setResults([]);
                    enqueueSnackbar('Results cleared', { variant: 'info' });
                  }}
                  startIcon={<DeleteIcon />}
                  sx={{
                    borderRadius: 2,
                    borderColor: 'error.main',
                    color: 'error.main',
                    '&:hover': {
                      borderColor: 'error.dark',
                      background: 'rgba(211, 47, 47, 0.04)'
                    }
                  }}
                >
                  Clear Results
                </Button>
              )}
            </Box>
            <Typography variant="body2" color="text.secondary">
              Upload an Excel file containing CVSS vectors to calculate scores
            </Typography>
          </Paper>
        </Box>

        {/* Results Section */}
        {results.length > 0 && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.3 }}
          >
            <StatsDisplay 
              stats={stats} 
              onExport={() => exportToExcel(results)}
              hasResults={results.length > 0}
            />
            <Box sx={{ mt: 3 }}>
              <ResultsTable results={results} />
            </Box>
          </motion.div>
        )}
      </Container>

      {/* Info Drawer */}
      <Drawer
        anchor="right"
        open={drawerOpen}
        onClose={() => setDrawerOpen(false)}
        PaperProps={{
          sx: {
            width: 400,
            background: darkMode 
              ? 'linear-gradient(135deg, #1a1a1a 0%, #2d3436 100%)'
              : 'linear-gradient(135deg, #f5f7fa 0%, #e3eeff 100%)',
            p: 3
          }
        }}
      >
        <Box sx={{ mb: 2 }}>
          <Typography variant="h5" gutterBottom fontWeight={600}>
            About CVSS Calculator
          </Typography>
          <Typography variant="body1" paragraph>
            The Common Vulnerability Scoring System (CVSS) provides a way to capture the principal characteristics of a vulnerability and produce a numerical score reflecting its severity.
          </Typography>
          <Typography variant="body1">
            This calculator supports CVSS v3.1 and can process:
          </Typography>
          <ul>
            <li>Individual CVSS vectors</li>
            <li>Excel files with multiple vectors</li>
            <li>Base, temporal, and environmental metrics</li>
          </ul>
        </Box>
      </Drawer>
    </Box>
  );
}

export default App;
