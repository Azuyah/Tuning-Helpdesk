#!/bin/bash
cd "$(dirname "$0")"
echo "🚀 Startar Tuning Helpdesk..."
/usr/bin/env node server.js
echo "✅ Körs nu på http://localhost:3000"
read -p "Tryck [Enter] för att stänga..."