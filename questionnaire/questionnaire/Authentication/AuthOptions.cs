﻿using Microsoft.IdentityModel.Tokens;
using System.Text;

namespace questionnaire.questionnaire.Authentication
{
    //Задаем параметры для создания токена
    public class AuthOptions
    {
        public const string ISSUER = "MyAuthServer"; // издатель токена
        public const string AUDIENCE = "MyAuthClient"; // потребитель токена
        public const string KEY = "mysupersecret_s1234567890123456ecretkey!";
        public const int LIFETIME = 10000; // время жизни токена - 1 минута
        public static string UserIdClaimType = "userId"; // Добавляем параметр для хранения ID пользователя

        public static SymmetricSecurityKey GetSymmetricSecurityKey()
        {
            return new SymmetricSecurityKey(Encoding.UTF8.GetBytes(KEY));
        }
    }
}