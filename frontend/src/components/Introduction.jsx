import React from "react";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "./ui/card";
import { Button } from "./ui/button";
import { Badge } from "./ui/badge";

export default function Introduction() {
  return (
    <div className="min-h-screen bg-background p-8">
      <div className="max-w-6xl mx-auto space-y-8">
        {/* Hero Section */}
        <div className="text-center space-y-4 py-12">
          <h1 className="text-5xl font-bold text-primary">
            Cyber Threat Intelligence Platform
          </h1>
          <p className="text-xl text-muted-foreground max-w-2xl mx-auto">
            Advanced threat analysis and security intelligence tools for modern cybersecurity professionals
          </p>
          <div className="flex gap-4 justify-center pt-6">
            <Button size="lg">Get Started</Button>
            <Button variant="outline" size="lg">Learn More</Button>
          </div>
        </div>

        {/* Feature Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          <Card className="hover:shadow-lg transition-shadow">
            <CardHeader>
              <Badge className="w-fit mb-2">IOC Tools</Badge>
              <CardTitle>Indicator Analysis</CardTitle>
              <CardDescription>
                Extract, analyze, and lookup indicators of compromise across multiple threat intelligence sources
              </CardDescription>
            </CardHeader>
            <CardContent>
              <ul className="space-y-2 text-sm text-muted-foreground">
                <li>• IOC Extractor</li>
                <li>• Bulk Lookup</li>
                <li>• Defanger Tools</li>
              </ul>
            </CardContent>
          </Card>

          <Card className="hover:shadow-lg transition-shadow">
            <CardHeader>
              <Badge className="w-fit mb-2" variant="secondary">Email Analyzer</Badge>
              <CardTitle>Email Security</CardTitle>
              <CardDescription>
                Comprehensive email header analysis and phishing detection capabilities
              </CardDescription>
            </CardHeader>
            <CardContent>
              <ul className="space-y-2 text-sm text-muted-foreground">
                <li>• Header Analysis</li>
                <li>• Attachment Scanning</li>
                <li>• URL Extraction</li>
              </ul>
            </CardContent>
          </Card>

          <Card className="hover:shadow-lg transition-shadow">
            <CardHeader>
              <Badge className="w-fit mb-2" variant="outline">Threat Feed</Badge>
              <CardTitle>News & Intelligence</CardTitle>
              <CardDescription>
                Real-time threat intelligence feeds and security news aggregation
              </CardDescription>
            </CardHeader>
            <CardContent>
              <ul className="space-y-2 text-sm text-muted-foreground">
                <li>• RSS Feed Monitoring</li>
                <li>• Trend Analysis</li>
                <li>• CVE Tracking</li>
              </ul>
            </CardContent>
          </Card>

          <Card className="hover:shadow-lg transition-shadow">
            <CardHeader>
              <Badge className="w-fit mb-2">Rule Creator</Badge>
              <CardTitle>Detection Rules</CardTitle>
              <CardDescription>
                Create and manage detection rules for SIEM and security tools
              </CardDescription>
            </CardHeader>
            <CardContent>
              <ul className="space-y-2 text-sm text-muted-foreground">
                <li>• Sigma Rules</li>
                <li>• Snort Rules</li>
                <li>• YARA Rules</li>
              </ul>
            </CardContent>
          </Card>

          <Card className="hover:shadow-lg transition-shadow">
            <CardHeader>
              <Badge className="w-fit mb-2" variant="secondary">CVSS Calculator</Badge>
              <CardTitle>Risk Assessment</CardTitle>
              <CardDescription>
                Calculate vulnerability severity scores using CVSS v3.1 methodology
              </CardDescription>
            </CardHeader>
            <CardContent>
              <ul className="space-y-2 text-sm text-muted-foreground">
                <li>• Base Score</li>
                <li>• Temporal Score</li>
                <li>• Environmental Score</li>
              </ul>
            </CardContent>
          </Card>

          <Card className="hover:shadow-lg transition-shadow">
            <CardHeader>
              <Badge className="w-fit mb-2" variant="outline">Domain Monitor</Badge>
              <CardTitle>Domain Intelligence</CardTitle>
              <CardDescription>
                Monitor and analyze domain registrations for threat detection
              </CardDescription>
            </CardHeader>
            <CardContent>
              <ul className="space-y-2 text-sm text-muted-foreground">
                <li>• WHOIS Lookup</li>
                <li>• DNS Analysis</li>
                <li>• Certificate Info</li>
              </ul>
            </CardContent>
          </Card>
        </div>

        {/* CTA Section */}
        <Card className="bg-primary text-primary-foreground">
          <CardHeader>
            <CardTitle className="text-3xl text-white">Ready to enhance your security posture?</CardTitle>
            <CardDescription className="text-primary-foreground/80">
              Start using our comprehensive threat intelligence platform today
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Button variant="secondary" size="lg">
              Explore Tools
            </Button>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
