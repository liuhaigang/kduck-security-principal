package cn.kduck.security;



import cn.kduck.core.service.ValueMap;

/**
 * 这是个覆盖适配类
 */
public interface UserExtInfo {

    ValueMap getUserExtInfo(String accountName);
}
