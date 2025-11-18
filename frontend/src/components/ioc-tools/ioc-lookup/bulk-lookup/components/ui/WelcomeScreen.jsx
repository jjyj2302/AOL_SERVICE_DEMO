import React from 'react';
import { Box, Paper, Typography, Grid } from '@mui/material';
import { CloudUpload, TextFields, Speed, Security } from '@mui/icons-material';

const SUPPORTED_IOC_TYPES_INFO = [
  { title: "IP Addresses", description: "위협 분석을 위한 IPv4 및 IPv6 주소" },
  { title: "Domains", description: "도메인 이름 및 서브도메인" },
  { title: "URLs", description: "웹 주소 및 엔드포인트" },
  { title: "Email Addresses", description: "알려진 악성 또는 의심스러운 이메일 주소" },
  { title: "Hashes", description: "MD5, SHA1, SHA256 파일 해시" },
  { title: "CVEs", description: "공통 취약점 및 노출 식별자" },
];

const BULK_FEATURES = [
  {
    icon: <Speed sx={{ fontSize: 40, color: 'primary.main' }} />,
    title: "Batch Processing",
    description: "수백 개의 IOC를 동시에 분석"
  },
  {
    icon: <CloudUpload sx={{ fontSize: 40, color: 'primary.main' }} />,
    title: "File Upload Support",
    description: "IOC가 포함된 CSV, TXT 또는 MD 파일 업로드"
  },
  {
    icon: <Security sx={{ fontSize: 40, color: 'primary.main' }} />,
    title: "Multiple Sources",
    description: "여러 위협 인텔리전스 소스를 병렬로 조회"
  },
  {
    icon: <TextFields sx={{ fontSize: 40, color: 'primary.main' }} />,
    title: "Flexible Input",
    description: "수동으로 입력하거나 클립보드에서 붙여넣기 - 한 줄에 하나의 IOC"
  },
];

const FeatureCard = ({ title, description }) => (
  <Grid item xs={12} sm={6} key={title}>
    <Paper elevation={0} sx={{ p: 1.5 }}>
      <Typography color="primary" fontWeight="medium" sx={{ fontSize: '0.9rem' }}>
        {title}
      </Typography>
      <Typography variant="body2" color="text.secondary" sx={{ fontSize: '0.8rem' }}>
        {description}
      </Typography>
    </Paper>
  </Grid>
);

const BulkFeatureCard = ({ icon, title, description }) => (
  <Grid item xs={12} sm={6} md={3}>
    <Paper elevation={0} sx={{ p: 2, textAlign: 'center', height: '100%' }}>
      <Box sx={{ mb: 1 }}>
        {icon}
      </Box>
      <Typography variant="h6" sx={{ fontSize: '1rem', fontWeight: 600, mb: 1 }}>
        {title}
      </Typography>
      <Typography variant="body2" color="text.secondary" sx={{ fontSize: '0.85rem' }}>
        {description}
      </Typography>
    </Paper>
  </Grid>
);

export default function WelcomeScreen() {
  return (
    <Paper sx={{ p: { xs: 2, sm: 3 }, mt: 2 }}>
      <Box sx={{ mb: 4 }}>
        <Typography variant="h5" component="h1" gutterBottom>
          Bulk IOC Lookup
        </Typography>
        <Typography paragraph>
          이 도구는 IOC를 일괄 처리하고, 자동으로 유형별로 분류하며,
          다양한 보안 서비스로부터 위협 인텔리전스 데이터를 제공합니다.
        </Typography>
        <Typography>
          IOC를 붙여넣거나 (한 줄에 하나씩) 파일을 업로드하여 시작하세요. 시스템이
          자동으로 IOC 유형을 감지하고 관련 위협 인텔리전스 소스를 병렬로 조회하여
          빠른 분석을 제공합니다.
        </Typography>
      </Box>

      <Grid container spacing={2} sx={{ mb: 4 }}>
        {BULK_FEATURES.map(item => (
          <BulkFeatureCard key={item.title} icon={item.icon} title={item.title} description={item.description} />
        ))}
      </Grid>

      <Typography variant="h6" component="h2" sx={{ mb: 2 }}>
        지원되는 IOC 유형
      </Typography>
      <Grid container spacing={1}>
        {SUPPORTED_IOC_TYPES_INFO.map(item => (
          <FeatureCard key={item.title} title={item.title} description={item.description} />
        ))}
      </Grid>
    </Paper>
  );
}
