@echo off
chcp 65001 > nul
echo.
echo  =========================================
echo    AgentGuard - AI 에이전트 보안 관제 데모
echo  =========================================
echo.

echo  [1/2] 의존성 설치 중...
pip install -q -r requirements.txt
if %errorlevel% neq 0 (
    echo  [오류] pip 설치 실패. Python이 설치되어 있는지 확인하세요.
    pause
    exit /b 1
)

echo.
echo  [2/2] 서버 시작 중...
echo.
echo  ============================================
echo   브라우저에서 http://localhost:8000 을 여세요!
echo  ============================================
echo.
echo  [Ctrl+C 를 눌러 서버를 종료하세요]
echo.

python main.py
pause
