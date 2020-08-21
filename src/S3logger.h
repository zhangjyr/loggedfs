/*****************************************************************************
 * Author:   Jingyuan Zhang <zhangjyr at gmail dot com>
 *****************************************************************************/
#ifndef LOGGEDFS_S3LOGGER_H
#define LOGGEDFS_S3LOGGER_H

#include "easylogging++.h"

#include <boost/asio.hpp>

class S3Dispatcher : public el::LogDispatchCallback
{
public:
    // Setters
    void setRegion(const std::string &region) { m_region = region; };
    void setBucket(const std::string &bucket) { m_bucket = bucket; };

protected:
    void handle(const el::LogDispatchData *data) noexcept override;

private:
    const el::LogDispatchData *m_data;
    std::string m_region;
    std::string m_bucket;

    void dispatch(el::base::type::string_t &&logLine) noexcept;
};