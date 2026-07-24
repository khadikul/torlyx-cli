"""App configuration. (Intentionally vulnerable fixture — every value is fake.)"""

# TLX-S010: JWT signing secret hardcoded
SECRET_KEY = "u9Tr4eWq2zXc8vBn6mAs1dFg"

# TLX-S003: Stripe live key
STRIPE_KEY = "sk_live_9rXt2pQv8mZw4nLb"

# TLX-S002: AWS access key
AWS_ACCESS_KEY_ID = "AKIAQWERTYUIOPASDFGH"

# TLX-S004: OpenAI API key
OPENAI_API_KEY = "sk-proj-Qw8rTn3xZb6vLm2pKd9fJh4sGc1aYe5u"

# TLX-S005: Anthropic API key
ANTHROPIC_API_KEY = "sk-ant-api03-Xk2mNp8rQt4vZw7yBc3dFg6hJl9s"

# TLX-S006: GitHub token
GITHUB_TOKEN = "ghp_Ab3Cd5Ef7Gh9Ij1Kl2Mn4Op6Qr8St0Uv2Wx4"

# TLX-S007: Google API key
GOOGLE_API_KEY = "AIzaSyB8xQ2mNp4rTv6zLc1dFg3hJk5sWy7aXe9"

# TLX-S008: Supabase service role key
SUPABASE_SERVICE_ROLE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImFiY2RlZmdoaWprbG1ub3AiLCJyb2xlIjoic2VydmljZV9yb2xlIiwiaWF0IjoxNzAwMDAwMDAwfQ.Zq7pXk3vNb9wRt5yUj2mHs8dQf4aLc6e"

# TLX-S001: generic high-entropy secret
PAYMENT_SIGNING_TOKEN = "Vq3xZ8pL1nRw6tYb2mKd9fJh4sGc7aQe"
