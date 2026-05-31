/**
 * 가운데 채팅 패널 — 순수 대화만 (NotebookLM 의 가운데 영역).
 *
 * messages: [{role: 'user'|'assistant', agent?: {emoji, label, color}, text, timestamp}]
 */
import { useEffect, useRef } from "react";
import {
  Avatar,
  Box,
  IconButton,
  InputBase,
  Paper,
  Stack,
  Typography,
  alpha,
  useTheme,
} from "@mui/material";
import SendIcon from "@mui/icons-material/Send";
import PersonIcon from "@mui/icons-material/Person";

function Bubble({ msg }) {
  const theme = useTheme();
  if (msg.role === "user") {
    return (
      <Stack direction="row" justifyContent="flex-end" mb={1.5}>
        <Paper
          sx={{
            p: 1.5,
            px: 2,
            maxWidth: "85%",
            borderRadius: "18px 18px 4px 18px",
            bgcolor: "primary.main",
            color: "primary.contrastText",
            boxShadow: "none",
          }}
        >
          <Typography variant="body2" sx={{ whiteSpace: "pre-wrap" }}>{msg.text}</Typography>
        </Paper>
        <Avatar sx={{ bgcolor: "primary.main", width: 32, height: 32, ml: 1, mt: 0.5 }}>
          <PersonIcon sx={{ fontSize: 18 }} />
        </Avatar>
      </Stack>
    );
  }

  // assistant
  const agent = msg.agent;
  return (
    <Stack direction="row" mb={1.5} spacing={1}>
      <Avatar
        sx={{
          bgcolor: agent ? alpha(agent.color, 0.2) : alpha(theme.palette.text.primary, 0.1),
          width: 32,
          height: 32,
          fontSize: 16,
          mt: 0.5,
        }}
      >
        {agent ? agent.emoji : "🤖"}
      </Avatar>
      <Box sx={{ flexGrow: 1, maxWidth: "85%" }}>
        {agent && (
          <Typography variant="caption" color="text.secondary" fontWeight={600} sx={{ display: "block", mb: 0.25, ml: 0.5 }}>
            {agent.label}
          </Typography>
        )}
        <Paper
          variant="outlined"
          sx={{
            p: 1.5,
            px: 2,
            borderRadius: "4px 18px 18px 18px",
            bgcolor: "background.paper",
            borderColor: "divider",
          }}
        >
          <Typography variant="body2" sx={{ whiteSpace: "pre-wrap", lineHeight: 1.6 }}>
            {msg.text}
          </Typography>
        </Paper>
      </Box>
    </Stack>
  );
}

export default function ChatPanel({ messages, input, onInputChange, onSubmit, streaming }) {
  const theme = useTheme();
  const endRef = useRef(null);

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, streaming]);

  const handleKey = (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      if (input.trim() && !streaming) onSubmit();
    }
  };

  return (
    <Box sx={{ display: "flex", flexDirection: "column", height: "calc(100vh - 130px)", minHeight: 500 }}>
      <Typography variant="overline" color="text.secondary" fontWeight={700} sx={{ display: "block", mb: 1.5 }}>
        💬 대화
      </Typography>

      {/* 메시지 리스트 */}
      <Paper
        variant="outlined"
        sx={{
          flexGrow: 1,
          borderRadius: "16px",
          p: 2,
          overflowY: "auto",
          bgcolor: alpha(theme.palette.text.primary, 0.01),
        }}
      >
        {messages.length === 0 ? (
          <Box sx={{ display: "flex", alignItems: "center", justifyContent: "center", height: "100%", color: "text.secondary" }}>
            <Box sx={{ textAlign: "center" }}>
              <Typography variant="h6" sx={{ mb: 1 }}>🤖 AI Threat Hunter</Typography>
              <Typography variant="body2">
                IoC (도메인 / IP / 해시 / CVE) 또는 분석 요청을 입력하세요.
                <br />
                좌측 자료실에서 샘플 시나리오를 클릭해도 시작됩니다.
              </Typography>
            </Box>
          </Box>
        ) : (
          messages.map((m, i) => <Bubble key={i} msg={m} />)
        )}
        <div ref={endRef} />
      </Paper>

      {/* 입력창 */}
      <Paper
        variant="outlined"
        sx={{
          mt: 1.5,
          borderRadius: "16px",
          p: 1,
          px: 1.5,
          display: "flex",
          alignItems: "center",
          gap: 1,
          borderColor: "divider",
        }}
      >
        <InputBase
          multiline
          maxRows={4}
          fullWidth
          placeholder={streaming ? "분석 중…" : "IoC 또는 분석 요청 입력 (Enter 전송)"}
          value={input}
          onChange={(e) => onInputChange(e.target.value)}
          onKeyDown={handleKey}
          disabled={streaming}
          sx={{ fontSize: 14 }}
        />
        <IconButton
          color="primary"
          onClick={onSubmit}
          disabled={streaming || !input.trim()}
          sx={{
            bgcolor: "primary.main",
            color: "primary.contrastText",
            "&:hover": { bgcolor: "primary.dark" },
            "&.Mui-disabled": { bgcolor: alpha(theme.palette.text.primary, 0.1) },
          }}
        >
          <SendIcon sx={{ fontSize: 18 }} />
        </IconButton>
      </Paper>
    </Box>
  );
}
