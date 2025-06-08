import bcrypt from "bcryptjs";

// 사용자의 비밀번호를 안전하게 저장하기 위해 "salt + hash" 처리를 하는 함수
export function saltAndHashPassword(password: string): string {
    const saltRounds = 10;
    const salt = bcrypt.genSaltSync(saltRounds);
    const hash = bcrypt.hashSync(password, salt);

    return hash;
}

// DB에 있는 비밀번호 vs 입력 받은 비밀번호 비교하는 함수
export function comparePasswords(password: string, hashedPassword: string): boolean {
    return bcrypt.compareSync(password, hashedPassword);
}