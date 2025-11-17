import React from 'react';
import {
  Box,
  Paper,
  Typography,
  Grid
} from '@mui/material';

export default function ExtractorWelcomeScreen() {
  const features = [
    {
      title: 'Automated Extraction',
      description: '정규 표현식을 사용하여 비정형 파일에서 IOC를 추출'
    },
    {
      title: 'Duplicate Removal',
      description: '결과에서 중복된 IOC를 자동으로 제거'
    },
    {
      title: 'Simple Interface',
      description: '설정 없이 파일을 드롭하고 결과를 바로 확인'
    },
    {
      title: 'One-Click Analysis',
      description: '감지된 각 IOC를 클릭 한 번으로 분석'
    }
  ];

  return (
    <Paper sx={{ p: 3 }}>
      <Typography variant="h6" sx={{ mb: 2 }}>
        IOC Extractor
      </Typography>
      
      <Box sx={{ mb: 4 }}>
        <Typography paragraph>
          IOC Extractor는 정규 표현식(Regex)을 사용하여 비정형 파일에서 침해 지표(IOC)를 추출하고
          정리할 수 있는 모듈입니다. 중복된 IOC를 자동으로 제거하므로 동일한 IOC를 여러 번 확인할
          필요가 없습니다.
        </Typography>
        <Typography>
          IOC가 포함된 파일을 도구에 드롭하기만 하면 자동으로 처리됩니다.
          클릭 한 번으로 감지된 모든 IOC를 분석할 수 있어, 수동으로 파일에서 IOC를 추출하기 위해
          엑셀 시트를 만드는 시간과 노력을 절약할 수 있습니다.
        </Typography>
      </Box>

      <Typography variant="h6" sx={{ mb: 2 }}>
        주요 기능
      </Typography>

      <Grid container spacing={1}>
        {features.map((feature, index) => (
          <Grid item xs={12} sm={6} key={index}>
            <Paper elevation={0} sx={{ p: 1 }}>
              <Typography color="primary" fontWeight="medium">
                {feature.title}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                {feature.description}
              </Typography>
            </Paper>
          </Grid>
        ))}
      </Grid>
    </Paper>
  );
}
