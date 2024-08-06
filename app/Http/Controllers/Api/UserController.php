<?php

namespace App\Http\Controllers\Api;

use App\Models\User;
use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Password;
use Illuminate\Support\Facades\Validator;

class UserController extends Controller
{

    public function register(Request $request)
    {
        $request->validate([
            "name" => "required|string|",
            "email" => "required|email|unique:users,email",
            "password" => "required|string|min:3",
        ]);

        $user = User::create([
            "name" => $request->name,
            "email" => $request,
            "password" => Hash::make($request->password),
        ]);
        return response()->json(["message" => "başarı ile kaydedildi"], 201);
    }

    public function login(Request $request)
    {

        $request->validate([
            "email" => "required|email",
            "password" => "required",
        ]);
        if (Auth::attempt($request->only("email", "password"))) {
            $user = User::where("email", $request->email)->first();
            $token = $user->crateToken("auth_token")->plainTextToken;
            return response()->json(["token", $token], 200);
        }
        return response()->json(["message", "Unauthorized"], 401);
    }

    //


    public function sendResetLinkEmail(Request $request)
    {

        $validator = Validator::make($request->all(), ['email' => 'required|email']);
        if ($validator->fails()) {
            return response()->json(['error' => $validator->errors()], 422);
        }

        $response = Password::sendResetLink($request->only('email'));
        return $response == Password::RESET_LINK_SENT
        ? response()->json(['message' => trans($response)])
        : response()->json(['error' => trans($response)], 500);
    }


    public function resetPassword(Request $request) {
        $validator = Validator::make($request->all(),
    [
        'token' =>'required',
        'email' =>'required|email',
        'password' => 'required|min:8|confirmed',
    ]);

    if ($validator->fails()) {
        return response()->json(['error' => $validator->errors()], 422);
    }
    $response =Password::reset(
        $request->only('email', 'password','password_confirmation', 'token'),
        function ($user, $password) {
                $user ->forceFill([
                    'password' => bcrypt($password),
                    'remember_token' => Str::random(60),
                ])->save();

        }
    );
    return $response == Password::PASSWORD_RESET
    ? response()->json(['message' => trans($response)])
    : response()->json(['error' => trans($response)], 500);
    }





}
