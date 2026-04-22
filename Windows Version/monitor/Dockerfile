FROM python:3.10-slim

WORKDIR /app

COPY requirements.txt .
# We only need 'requests' now; no more GUI libraries
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install --no-cache-dir requests

COPY . .

# Run the new terminal-based monitor
CMD ["python", "-u", "monitor_cli.py"]