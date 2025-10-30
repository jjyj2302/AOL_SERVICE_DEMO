import { forwardRef } from "react";
import { TextField, Button, InputAdornment, useTheme } from "@mui/material";
import SearchIcon from "@mui/icons-material/Search";

const SearchBar = forwardRef(
  ({ value, placeholder = "Enter something...", onChange, onKeyDown, onSearchClick, buttonLabel = "Search", size = "medium" }, ref) => {
    const theme = useTheme();
    const isLightMode = theme.palette.mode === 'light';

    const inputHeight = size === "large" ? "64px" : "56px";
    const fontSize = size === "large" ? "1.125rem" : "1rem";
    const buttonSize = size === "large" ? "large" : "medium";

    return (
      <TextField
        fullWidth
        variant="outlined"
        value={value}
        placeholder={placeholder}
        onChange={onChange}
        onKeyDown={onKeyDown}
        inputRef={ref}
        sx={{
          "& .MuiOutlinedInput-root": {
            backgroundColor: isLightMode ? '#ffffff' : theme.palette.background.paper,
            borderRadius: '12px',
            height: inputHeight,
            fontSize: fontSize,
            "& fieldset": {
              border: isLightMode ? '1px solid rgba(0,0,0,0.12)' : 'none',
            },
            "&:hover fieldset": {
              border: isLightMode ? '1px solid rgba(0,0,0,0.2)' : 'none',
            },
            "&.Mui-focused fieldset": {
              border: isLightMode ? `2px solid ${theme.palette.primary.main}` : 'none',
            },
          },
          "& .MuiInputBase-input": {
            fontSize: fontSize,
          },
        }}
        InputProps={{
          endAdornment: (
            <InputAdornment position="end">
              <Button
                variant="contained"
                color="primary"
                startIcon={<SearchIcon />}
                onClick={onSearchClick}
                size={buttonSize}
                sx={{
                  ml: 1.25,
                  borderRadius: 2,
                  boxShadow: "none",
                  "&:hover": { boxShadow: "none" },
                }}
              >
                {buttonLabel}
              </Button>
            </InputAdornment>
          ),
        }}
      />
    );
  }
);

export default SearchBar;
