import anticaptchaofficial.geetestproxyless
from nonebot import get_driver, require
from typing import List
from nonebot import require
from nonebot import on_command
from nonebot.adapters import Bot, Event
from nonebot.log import logger
from nonebot.plugin import PluginMetadata

require("nonebot_plugin_saa")
require("nonebot_plugin_mys_api")
require("nonebot_plugin_srbind")

from nonebot_plugin_saa import MessageFactory, Text

try:
    from march7th.nonebot_plugin_mys_api import mys_api
    from march7th.nonebot_plugin_srbind import get_user_srbind
    from march7th.nonebot_plugin_srbind.cookie import get_user_cookie
except ModuleNotFoundError:
    from nonebot_plugin_mys_api import mys_api
    from nonebot_plugin_srbind import get_user_srbind
    from nonebot_plugin_srbind.cookie import get_user_cookie

__plugin_meta__ = PluginMetadata(
    name="StarRailSign",
    description="崩坏：星穹铁道米游社签到",
    usage="srsign",
    extra={
        "version": "1.0",
        "srhelp": """\
每日签到: srsign
""",
    },
)

error_code_msg = {
    10001: "绑定cookie失效，请重新绑定",
    -10001: "请求出错，请尝试重新使用`srqr`绑定",
    -5003: "今日已签到",
}

srsign = on_command("srsign", aliases={"星铁签到", "星铁每日签到"}, priority=2, block=True)


@srsign.handle()
async def _(bot: Bot, event: Event):
    user_id = event.get_user_id()
    user_list = await get_user_srbind(bot.self_id, user_id)
    if not user_list:
        err = "未绑定SRUID，请使用`srck [cookie]`绑定或`srqr`扫码绑定"
        msg_builder = MessageFactory([Text(err)])
        await msg_builder.send(at_sender=True)
        await srsign.finish()
    message = MessageFactory([Text(str(f"开始执行签到，请等待"))])
    await message.send(at_sender=True)
    msg: List[str] = []
    for user in user_list:
        sr_uid = user.sr_uid
        cookie = await get_user_cookie(bot.self_id, user_id, sr_uid)
        if not cookie:
            msg.append(f"SRUID{sr_uid}: 未绑定cookie，请使用`srck [cookie]`绑定或`srqr`扫码绑定")
            continue
        logger.info(f"开始为SRUID『{sr_uid}』签到")
        sr_sign = await mys_api.call_mihoyo_api(
            "sr_sign", cookie=cookie, role_uid=sr_uid
        )
        if not sr_sign:
            msg.append(f"SRUID{sr_uid}: 疑似cookie失效，请重新使用`srck [cookie]`绑定或`srqr`扫码绑定")
            msg_builder = MessageFactory([Text(str(msg))])
            await msg_builder.send(at_sender=True)
            await srsign.finish()
        if isinstance(sr_sign, int):
            if sr_sign in error_code_msg:
                msg.append(f"SRUID{sr_uid}: {error_code_msg[sr_sign]}")
            else:
                msg.append(f"SRUID{sr_uid}: 签到失败（错误代码 {sr_sign}）")
            continue
        is_risk = sr_sign.get("is_risk")
        if is_risk is True:
            # msg.append(f"UID{sr_uid}: 签到遇验证码，请手动签到")
            #message = MessageFactory([Text(str(f"SRUID{sr_uid}：签到遇验证码，正在尝试绕过"))])
            #await message.send(at_sender=True)
            try:
                captcha_result, captcha_data = await captcha_handler(sr_sign)
                if captcha_result == 1:
                    msg.append(captcha_data)
                    continue
                else:
                    extra_headers = await geetest_validate_header(geetest_challenge=captcha_data["challenge"],
                                                                  geetest_seccode=captcha_data["seccode"],
                                                                  geetest_validate=captcha_data["validate"])
                    sr_sign = await mys_api.call_mihoyo_api(
                        "sr_sign", cookie=cookie, role_uid=sr_uid, extra_headers=extra_headers
                    )
            except NotImplementedError:
                continue
            except RuntimeError:
                msg.append(f"SRUID{sr_uid}: 签到失败（内部错误）")
                continue
        if isinstance(sr_sign, int):
            if sr_sign in error_code_msg:
                msg.append(f"SRUID{sr_uid}: {error_code_msg[sr_sign]}")
            else:
                msg.append(f"SRUID{sr_uid}: 签到失败（错误代码 {sr_sign}）")
            continue
        msg.append(f"UID{sr_uid}: 签到成功")
    msg_builder = MessageFactory([Text("\n" + "\n".join(msg))])
    await msg_builder.send(at_sender=True)
    await srsign.finish()


async def captcha_handler(sign_data: dict):
    import nonebot
    global_config = nonebot.get_driver().config
    captcha_enable = global_config.captcha_enabled
    logger.debug(captcha_enable)
    if captcha_enable == 0:
        await srsign.send(f"签到遇验证码，请联系管理员开启验证码绕过")
        raise NotImplementedError()
    captcha_api_key = global_config.captcha_handler_api_key
    captcha_endpoint = global_config.captcha_handler_api_endpoint
    page_url = "https://webstatic.mihoyo.com/bbs/event/signin/hkrpg/e202304121516551.html"
    gt = sign_data["gt"]
    challenge = sign_data["challenge"]
    captcha_result, err_string = await geetest_get_result(api_key=captcha_api_key, api_endpoint=captcha_endpoint,
                                                          gt=gt, challenge=challenge, page_url=page_url)
    if err_string == "":
        return 0, captcha_result
    else:
        return 1, "解析验证码时出现错误。错误信息" + err_string


async def geetest_get_result(api_key: str,
                             api_endpoint: str,
                             gt: str,
                             challenge: str,
                             page_url: str):
    solver = anticaptchaofficial.geetestproxyless.geetestProxyless()
    solver.set_verbose(1)
    solver.set_key(api_key)
    solver.set_website_url(page_url)
    logger.debug(gt)
    logger.debug(challenge)
    solver.set_gt_key(gt)
    solver.set_challenge_key(challenge)

    token = solver.solve_and_return_solution()
    logger.debug(token)
    logger.debug(solver.err_string)
    token = token
    return token, solver.err_string


async def geetest_validate_header(geetest_challenge: str,
                                  geetest_seccode: str,
                                  geetest_validate: str):
    if (geetest_challenge == "" or geetest_challenge is None
            or geetest_seccode == "" or geetest_seccode is None
            or geetest_validate == "" or geetest_validate is None):
        raise RuntimeError("验证码平台返回数据格式不对，请联系管理员")
    return {
        "x-rpc-validate": geetest_validate,
        "x-rpc-challenge": geetest_challenge,
        "x-rpc-seccode": geetest_seccode
    }
