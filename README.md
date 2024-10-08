# simple-auth

# README สำหรับโปรเจกต์ Flask-PostgreSQL-Redis

## คำอธิบาย

โปรเจกต์นี้เป็นเว็บแอปพลิเคชันที่สร้างด้วย **Flask** ซึ่งใช้ **PostgreSQL** เป็นฐานข้อมูลและ **Redis** สำหรับการจัดการเซสชันและการควบคุมการเข้าสู่ระบบ ระบบนี้มีฟังก์ชันการลงทะเบียนและการเข้าสู่ระบบ รวมถึงการจัดการการพยายามเข้าสู่ระบบที่ผิดพลาดและการแบนผู้ใช้ที่พยายามเข้าสู่ระบบหลายครั้ง

## เทคโนโลยีที่ใช้

- **Flask**: ใช้ในการพัฒนาเว็บแอปพลิเคชัน
- **PostgreSQL**: ฐานข้อมูลสำหรับจัดเก็บข้อมูลผู้ใช้
- **Redis**: ใช้สำหรับจัดการเซสชันและควบคุมการพยายามเข้าสู่ระบบ
- **Docker**: ใช้ในการสร้างสภาพแวดล้อมการพัฒนาที่สามารถทำซ้ำได้

## การติดตั้งและการตั้งค่า

1. **Clone Repository**
   ```bash
   git clone <URL ของ Repository>
   cd <ชื่อของ Repository>
   ```

2. **ตั้งค่าตัวแปรสภาพแวดล้อม**
   สร้างไฟล์ `.env` ในโฟลเดอร์หลักของโปรเจกต์และเพิ่มค่าตัวแปรสภาพแวดล้อม:
   ```
   POSTGRES_PASSWORD=your_postgres_password
   ```

3. **ติดตั้ง Docker และ Docker Compose**
   หากยังไม่ได้ติดตั้ง Docker และ Docker Compose โปรดติดตั้งตามคู่มือการติดตั้ง Docker และ Docker Compose

4. **สร้างและรันคอนเทนเนอร์**
   ใช้คำสั่งนี้เพื่อสร้างและรันคอนเทนเนอร์ Docker:
   ```bash
   docker-compose up --build
   ```

5. **เริ่มต้นฐานข้อมูล**
   ไฟล์ `init_db.sql` จะถูกใช้เพื่อเริ่มต้นฐานข้อมูล PostgreSQL โปรดตรวจสอบว่าไฟล์นี้มีอยู่และมีคำสั่ง SQL ที่ถูกต้อง

## การใช้งาน

- **ลงทะเบียนผู้ใช้:** ไปที่ `/register` เพื่อลงทะเบียนผู้ใช้ใหม่ ป้อนชื่อผู้ใช้และรหัสผ่านของคุณ
- **เข้าสู่ระบบ:** ไปที่ `/login` เพื่อเข้าสู่ระบบ ป้อนชื่อผู้ใช้และรหัสผ่านของคุณ
- **ออกจากระบบ:** ไปที่ `/logout` เพื่อออกจากระบบ

## การทดสอบ

- **ทดสอบการเข้าสู่ระบบ:** ลองเข้าสู่ระบบด้วยข้อมูลที่ถูกต้องและข้อมูลที่ผิดพลาด ตรวจสอบว่าระบบทำงานตามที่คาดหวัง
- **ตรวจสอบการจัดการเซสชัน:** ตรวจสอบว่าเซสชันทำงานได้อย่างถูกต้องโดยการตรวจสอบการเข้าสู่ระบบและการออกจากระบบ

## การตั้งค่า Docker Compose

- **web:** รันแอปพลิเคชัน Flask ตั้งค่าให้รอ 15 วินาทีเพื่อให้ฐานข้อมูลและ Redis พร้อมใช้งานก่อนที่จะเริ่มแอปพลิเคชัน
- **db:** รันฐานข้อมูล PostgreSQL ใช้ `init_db.sql` เพื่อเริ่มต้นฐานข้อมูล
- **redis:** รัน Redis สำหรับจัดการเซสชัน

## อ้างอิง

- [Flask Documentation](https://flask.palletsprojects.com/)
- [PostgreSQL Documentation](https://www.postgresql.org/docs/)
- [Redis Documentation](https://redis.io/documentation)
- [Docker Documentation](https://docs.docker.com/)
- [Docker Compose Documentation](https://docs.docker.com/compose/)
