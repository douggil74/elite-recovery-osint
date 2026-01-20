#!/bin/bash
# Elite Recovery OSINT Backend Deployment Script

echo "=========================================="
echo "Elite Recovery OSINT Backend Deployment"
echo "=========================================="
echo ""

# Check for available deployment options
check_render() {
    if [ -n "$RENDER_API_KEY" ]; then
        echo "✓ Render API key found"
        return 0
    fi
    return 1
}

check_railway() {
    if command -v railway &> /dev/null && railway whoami &> /dev/null; then
        echo "✓ Railway CLI authenticated"
        return 0
    fi
    return 1
}

check_fly() {
    if command -v flyctl &> /dev/null && flyctl auth whoami &> /dev/null; then
        echo "✓ Fly.io CLI authenticated"
        return 0
    fi
    return 1
}

check_gh() {
    if command -v gh &> /dev/null && gh auth status &> /dev/null; then
        echo "✓ GitHub CLI authenticated"
        return 0
    fi
    return 1
}

echo "Checking deployment options..."
echo ""

# Try each platform
if check_fly; then
    echo ""
    echo "Deploying to Fly.io..."
    flyctl deploy --now
    echo ""
    echo "✅ Deployed! Your API will be at: https://elite-recovery-osint.fly.dev"
    exit 0
fi

if check_railway; then
    echo ""
    echo "Deploying to Railway..."
    railway up
    echo ""
    echo "✅ Deployed to Railway!"
    exit 0
fi

if check_gh; then
    echo ""
    echo "Creating GitHub repo and deploying to Render..."
    gh repo create elite-recovery-osint --public --source=. --push
    echo ""
    echo "Repository created! Now deploy on Render.com:"
    echo "1. Go to https://render.com"
    echo "2. New + → Web Service"
    echo "3. Connect your GitHub repo: elite-recovery-osint"
    echo "4. Click Deploy"
    exit 0
fi

# No authentication found
echo ""
echo "❌ No authenticated deployment service found."
echo ""
echo "Choose a deployment option:"
echo ""
echo "OPTION 1: Fly.io (Recommended)"
echo "  1. Run: brew install flyctl"
echo "  2. Run: flyctl auth login"
echo "  3. Run this script again"
echo ""
echo "OPTION 2: Railway"
echo "  1. Run: npm install -g @railway/cli"
echo "  2. Run: railway login"
echo "  3. Run this script again"
echo ""
echo "OPTION 3: Render.com (Web Dashboard)"
echo "  1. Go to https://render.com"
echo "  2. Sign up/Login with GitHub"
echo "  3. New + → Web Service → Upload Files"
echo "  4. Upload the ZIP file at: $(dirname $0)/../osint-backend-deploy.zip"
echo "  5. Set start command: uvicorn main:app --host 0.0.0.0 --port \$PORT"
echo ""
echo "OPTION 4: Authenticate GitHub first"
echo "  1. Run: gh auth login"
echo "  2. Run this script again"
