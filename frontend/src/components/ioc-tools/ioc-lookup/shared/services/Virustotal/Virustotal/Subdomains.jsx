import React from "react";
import { useState } from "react";

import Button from "@mui/material/Button";
import Card from "@mui/material/Card";
import Grid from "@mui/material/Grid";
import { Typography } from "@mui/material";
import Box from "@mui/material/Box";

import DnsIcon from "@mui/icons-material/Dns";

export default function Subdomains(props) {
  const [expanded, setExpanded] = useState(false);
  const subdomains = props.result?.data?.attributes?.subdomains || [];

  const displayLimit = 20;
  const shouldShowExpandButton = subdomains.length > displayLimit;
  const displayedSubdomains = expanded ? subdomains : subdomains.slice(0, displayLimit);

  const toggleExpanded = () => {
    setExpanded(!expanded);
  };

  return (
    <Card
      key="subdomains_card"
      sx={{ m: 1, p: 2, borderRadius: 1, boxShadow: 0 }}
    >
      <Grid container alignItems="center">
        <Grid mr={1} item>
          <DnsIcon />
        </Grid>
        <Grid item>
          <Typography variant="h5" component="h2" gutterBottom>
            Subdomains ({subdomains.length})
          </Typography>
        </Grid>
      </Grid>

      {subdomains.length > 0 ? (
        <>
          <Box sx={{ whiteSpace: "pre-wrap" }}>
            {displayedSubdomains.map((subdomain, index) => (
              <Typography key={index} component="p" variant="body2" sx={{ py: 0.25 }}>
                • {subdomain}
              </Typography>
            ))}
          </Box>

          {shouldShowExpandButton && (
            <Button onClick={toggleExpanded} sx={{ mt: 1 }}>
              {expanded ? `Show Less` : `Show All (${subdomains.length - displayLimit} more)`}
            </Button>
          )}
        </>
      ) : (
        <Typography component="p" variant="body2" color="text.secondary">
          No subdomains found
        </Typography>
      )}
    </Card>
  );
}
