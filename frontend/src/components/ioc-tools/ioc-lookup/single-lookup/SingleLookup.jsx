import React, { useState, useCallback, useEffect } from "react";
import { useSetRecoilState } from "recoil";
import { useLocation } from "react-router-dom";
import { Alert, AlertTitle, Box, Grow } from "@mui/material";
import ResultTable from "./components/ui/ResultTable";
import WelcomeScreen from "./components/ui/WelcomeScreen";
import { determineIocType } from "../shared/utils/iocDefinitions";
import { searchHistoryState } from "../../../../state";

const Analyzer = () => {
  const [searchValue, setSearchValue] = useState("");
  const [currentIocType, setCurrentIocType] = useState("");
  const [isInputInvalid, setIsInputInvalid] = useState(false);
  const [shouldShowTable, setShouldShowTable] = useState(false);
  const setSearchHistory = useSetRecoilState(searchHistoryState);
  const location = useLocation();

  const handleValidation = useCallback((iocInput) => {
    const trimmedIoc = iocInput.trim();

    if (!trimmedIoc) {
      setShouldShowTable(false);
      setIsInputInvalid(false);
      setSearchValue("");
      setCurrentIocType("");
      return false;
    }

    const type = determineIocType(trimmedIoc);

    if (type !== 'unknown') {
      setIsInputInvalid(false);
      setSearchValue(trimmedIoc);
      setCurrentIocType(type);
      setShouldShowTable(true);

      // Add to search history
      setSearchHistory((prevHistory) => {
        const newEntry = {
          id: Date.now(),
          ioc: trimmedIoc,
          type: type,
          timestamp: new Date().toISOString(),
        };

        // Keep only last 20 searches and avoid duplicates
        const filtered = prevHistory.filter(item => item.ioc !== trimmedIoc);
        return [newEntry, ...filtered].slice(0, 20);
      });

      return true;
    } else {
      setShouldShowTable(false);
      setIsInputInvalid(true);
      return false;
    }
  }, [setSearchHistory]);

  const handleCloseError = useCallback(() => {
    setIsInputInvalid(false);
  }, []);

  // Handle search from history
  useEffect(() => {
    if (location.state?.searchIoc) {
      handleValidation(location.state.searchIoc);
      // Clear the state to prevent re-triggering
      window.history.replaceState({}, document.title);
    }
  }, [location.state, handleValidation]);

  return (
    <>
      <Box sx={{ my: 1 }}>
        {isInputInvalid && (
          <Grow in={true}>
            <Alert
              severity="error"
              variant="filled"
              onClose={handleCloseError}
              sx={{ borderRadius: 1 }}
            >
              <AlertTitle>
                <b>Invalid Input</b>
              </AlertTitle>
              Please enter a supported IOC type. The entered value does not match
              known formats for IP, Domain, URL, Email, Hash, or CVE.
            </Alert>
          </Grow>
        )}
      </Box>

      {shouldShowTable && searchValue && currentIocType ? (
        <ResultTable
          ioc={searchValue}
          iocType={currentIocType}
        />
      ) : (
        <WelcomeScreen onSubmit={handleValidation} />
      )}
    </>
  );
};

export default Analyzer;
