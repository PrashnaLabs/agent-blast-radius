FROM python:3.12-slim
WORKDIR /app
COPY . .
RUN pip install -r requirements.txt
# installs at container start: needs the internet every boot
CMD ["sh", "-c", "pip install sentence-transformers &&python agent.py"]
