# ใช้ Python 3.10
FROM python:3.10

# ตั้งค่า working directory
WORKDIR /app

# คัดลอกไฟล์ requirements.txt ไปยัง container
COPY requirements.txt requirements.txt

# ติดตั้ง dependencies
RUN pip install -r requirements.txt

# คัดลอกโค้ดทั้งหมดไปยัง container
COPY . .


