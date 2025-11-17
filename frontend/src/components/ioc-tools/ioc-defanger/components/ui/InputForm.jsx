import React from 'react';
import {
  TextField,
  Button,
  Stack
} from '@mui/material';
import {
  HealthAndSafety as HealthAndSafetyIcon,
  GppMaybe as GppMaybeIcon,
  Clear as ClearIcon,
  ContentCopy as CopyIcon
} from '@mui/icons-material';

const InputForm = ({ 
  inputText, 
  onInputChange, 
  operation, 
  onProcess, 
  onClear, 
  onCopyAllResults,
  hasResults 
}) => {
  return (
    <>
      <TextField
        fullWidth
        multiline
        rows={8}
        variant="outlined"
        label={`${operation === 'defang' ? 'Defang' : 'Fang'}할 IOC를 입력하세요 (한 줄에 하나씩)`}
        placeholder={operation === 'defang'
          ? "https://example.com\n192.168.1.1\nuser@domain.com\nmalware.exe"
          : "hxxps[://]example[.]com\n192[.]168[.]1[.]1\nuser[@]domain[.]com"
        }
        value={inputText}
        onChange={(e) => onInputChange(e.target.value)}
        helperText={`Domain, IP, URL, Email, Hash를 지원합니다. ${inputText.split('\n').filter(line => line.trim()).length}개 입력됨.`}
      />
      
      <Stack direction="row" spacing={2} sx={{ mt: 2 }}>
        <Button
          variant="contained"
          onClick={onProcess}
          disabled={!inputText.trim()}
          startIcon={operation === 'defang' ? <HealthAndSafetyIcon /> : <GppMaybeIcon />}
        >
          {operation === 'defang' ? 'IOC Defang' : 'IOC Fang'}
        </Button>
        <Button
          variant="outlined"
          onClick={onClear}
          startIcon={<ClearIcon />}
        >
          지우기
        </Button>
        {hasResults && (
          <Button
            variant="outlined"
            onClick={onCopyAllResults}
            startIcon={<CopyIcon />}
          >
            전체 결과 복사
          </Button>
        )}
      </Stack>
    </>
  );
};

export default InputForm;
